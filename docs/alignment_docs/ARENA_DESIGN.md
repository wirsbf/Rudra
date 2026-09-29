# ARENA_DESIGN — 全库 arena/索引化重构设计

> **目标**: 同时消灭 (a) `Arc<RwLock<T>>` 全覆盖形态的锁/克隆/原子/深拷贝速度地板,与 (b) 裸指针
> alias 类 unsafe——在**行为恒等红线**下完成。用户已放行全库重构(2026-09-30)。
>
> - 设计日期: 2026-09-30;设计基线 = master **65812a9b**(MB48 收官: canon curl 0/httpd 0;
>   镜面 curl 13/httpd 2/vsh 0/sq 432/sqlite 845;tests 1985P;VdbeExec 单极 45.92s =
>   oracle 8.8s 的 **5.2×**,全语料 --jobs 32 wall 46.62s)。
> - oracle = 锁定 **e40ed130**(Ghidra 12.0.4)。本文引用的 oracle 行号全部亲读核验
>   (funcdata.hh / op.hh / op.cc / varnode.hh / varnode.cc / block.hh / architecture.hh)。
> - 证据底座: INTERSECTCACHE / BLOCKSTRUCT / VARMAPOPCREATE / SLEIGHSNAP / SPEEDPROF2
>   五道终报(/dev/shm/rugra-reports/LANE_*_2026-09-29.md),全部为事件级探针实测数字。
> - campaign: `PERF-ARENA-MIGRATION-0001`(见 docs/TODO_BOARD.md)。

---

## §0 执行摘要与决策记录

**诊断**: Rugra 现形态是"对齐优先时期的保守安全直译"——oracle 的裸指针交叉引用
(PcodeOp/Varnode/FlowBlock 互相指)被翻译成 `Arc<RwLock<T>>` + `Weak`,结果是每个字段读都付
锁守卫+原子+引用计数+克隆税。五道速度道已把**算法本体**逐一对到 oracle 同构(尝试次数/迁移
次数/序全部相同,canon 0/0 旁证),残差集中在三类**实现级常数**:

1. **锁面**: 12,050 个 `.read()/.write()` 调用点(53/81 文件);INTERSECTCACHE 实测
   **136.6M 次锁读,99.65% 空手**(update_high 逐实例扫描,oracle 是 O(1) 标志判)。
2. **克隆/原子面**: BLOCKSTRUCT 实测 **53.4M 次 BlockEdge 克隆**(每次 2 原子 RMW + pred
   RwLock + 2 vtable + SipHash,~70ns/边);规则 miss 底 ~110ns/试 × 36M;`Weak` 升级
   (vn.def/descend)每次 2 原子+分支。
3. **簿记形态差**: VARMAPOPCREATE 实测 mark_dead `retain` O[n] 扫描 207,611 次/5.58s
   (均值 32.6K 元素),oracle 是**存储迭代器 O(1) erase**(op.cc:1017-1034)——尾部 pop
   快速路径只是补偿,非根治。

**结论**: 这三类残差的共同根因是**数据结构形态**,不是算法。oracle 的形态是:
Funcdata 拥有一切、裸指针交叉引用、单线程 Action 域、零锁零引用计数零 vtable 内联字段读。
arena/索引化 = 在 Rust 里**无 unsafe 地重建同一形态**: id 空间的裸指针(句柄) +
Funcdata 属主(god-object,oracle 本来就是)+ 存储链结构的 1:1 镜像(链表序/树键/图向量)。

### 决策记录(速查)

| # | 决策 | 判定 | 依据(详节) |
|---|---|---|---|
| D1 | ops/varnodes/blocks 三类**独立 arena**,Funcdata 属主 | 采纳 | §1.1-1.4 |
| D2 | BlockEdge **值化**(12B Copy,无 arena,留在 per-block Vec) | 采纳 | §1.5;oracle block.hh:57-65 |
| D3 | 跨函数共享物(Architecture/Sleigh)**保持 `Arc<Architecture>` 共享**,不进 per-fd arena | 采纳 | §1.6 |
| D4 | typed newtype id(u32 idx + u32 gen,8B=oracle 指针宽) | 采纳 | §2.1 |
| D5 | **手写 arena**(Vec<slot> + free-list + gen),不用 slotmap crate | 采纳 | §2.2 |
| D6 | alive/dead/opcode 列表 = **id 空间侵入式双向链表**(= std::list 的 O(1) splice/erase);**禁 swap-remove** | 采纳(红线) | §2.3 |
| D7 | varnode loc/def 树 = `BTreeMap<POD键, VnId>` + **槽内反规范化键副本**(= 存储迭代器) | 采纳 | §2.3 |
| D8 | 借用纪律主形态 = **`&mut Funcdata` god-object**(oracle friend-class 证据)+ 分域拆借 + id-pair helper;RefCell/GhostCell/桥接 enum 否决 | 采纳 | §3 |
| D9 | 迁移 = **W0 spike(arena core 先行) + W1 单分支原子类型翻转**(单 crate 无部分编译态),拒绝代码级双形态桥接 | 采纳 | §4 |
| D10 | 行为恒等红线 = canon 0/0/0 == 钉值 md5 + 镜面五面 == 钉值 + sqlite 全语料 assembled cmp 恒等 + tests 数恒等;**任何非恒等立即停** | 采纳(红线) | §4/§8 |
| D11 | transform.rs `*mut Funcdata`/`unsafe impl Send` 系、float_emulate libc、null_slot_sentinel 胶水**随 W1 消灭**;ffi.rs(测试工具)cfg 隔离 | 采纳 | §3.4 |
| D12 | SLEIGHSNAP 74ms 图物化地板**不在本 campaign 范围**(Architecture 域,诚实标注预期零改善) | 记录 | §7 |

---

## §1 ① 容器布局 — oracle 成员逐项映射

### 1.1 Funcdata 成员映射表(funcdata.hh:74-100 逐项)

| oracle 成员(funcdata.hh 行) | 现状(Rugra) | arena 形态 | 说明 |
|---|---|---|---|
| `flags` + 4 个 create-index/相位标记(:74-78) | 平面字段 | 保持 | 无句柄语义 |
| `Architecture *glb`(:80) | `Option<Arc<Architecture>>` | **保持 Arc 共享** | 见 §1.6;oracle 同为跨函数共享裸指针 |
| `FunctionSymbol *functionSymbol`(:81) | 数据库存属 | 保持 | Database 域,不进本 campaign 写域 |
| `name/displayName/baseaddr/funcp`(:82-85) | 平面值 | 保持 | |
| `ScopeLocal *localmap`(:86) | varmap 域 | 保持(接口经 query_properties) | ScopeLocal 符号查询已由 HERITAGE 道 memo 化;域独立 |
| `vector<FuncCallSpecs*> qlst`(:88) | Vec<…> | W3 可选:`Vec<CallSpecId>` | 低频 churn;`Arc::as_ptr` memo 键(funcdata.rs:2185)换 id |
| `vector<JumpTable*> jumpvec`(:89) | Vec<Arc<…>> | W3 可选:同上 | jt_ptr memo 键(funcdata.rs:5040)换 id |
| `VarnodeBank vbank`(:91) | `BTreeSet`+锁序比较器 | **`vn_arena: VnArena`** | §1.3 |
| `PcodeOpBank obank`(:92) | `PcodeOpTree`(BTreeMap)+Vec 列表 | **`op_arena: OpArena`** | §1.2 |
| `BlockGraph bblocks/sblocks`(:93-94) | `Vec<Arc<RwLock<dyn FlowBlock>>>` | **`block_arena: BlockArena` + 两个 `BlockGraph`(Vec<BlockId>)** | §1.4 |
| `Heritage heritage`(:95) | 平面值 | 保持(算法状态) | 内部引用句柄随 W1 换 id |
| `Merge covermerge`(:96) | 平面值 | 保持(句柄随 W1 换 id;HighVariable 见 §3.2) | |
| `activeoutput/localoverride/lanedMap/unionMap`(:97-100) | 平面值 | 保持 | |

**属主判决**: 三 arena 全部是 `Funcdata` 的**直接字段**(不是全局/不是 Arc)——这正是
oracle 的"Funcdata 拥有一切"(funcdata.hh:41-46 类注释:"This class holds the primary data
structures for decompiling a function")。三个 arena 是不同字段 ⇒ Rust 分域借用天然成立
(§3.2 的关键前提)。

### 1.2 OpArena — PcodeOpBank 1:1 镜像(op.hh:289-301 / op.cc:935-1015)

oracle PcodeOpBank = `map<SeqNum,PcodeOp*> optree` + **7 条 `list<PcodeOp*>`**
(deadlist/alivelist/storelist/loadlist/returnlist/useroplist/deadandgone,op.hh:291-297)
+ `uintm uniqid`。PcodeOp 自身存 3 个迭代器定位自己(op.hh:127-129):
`basiciter`(块内 op 表位置)/`insertiter`(alive/dead 表位置)/`codeiter`(opcode 表位置)
——**存储迭代器 = O(1) erase 的机制本体**。

```rust
// 槽位主存储(替代 new/delete 分配器)
enum OpSlot { Occupied(Box<OpData>), Free { next: Option<u32> } }

pub struct OpData {           // op.hh:122-131 逐字段
    opcode: OpCode,           // :122 TypeOp* → 枚举 id(行为表在 Architecture)
    flags: u32, addlflags: u32,   // :123-124
    start: SeqNum,            // :125(创建后不可变;order 字段可 setOrder,排序键不含)
    parent: Option<BlockId>,  // :126 BlockBasic*
    output: Option<VnId>,     // :130 Varnode*
    inrefs: Vec<Option<VnId>>, // :131 vector<Varnode*>;NULL slot = None
                              //   → 现有 null_slot_sentinel 胶水(SB-ORD159)整体删除
    // ---- op.hh:127-129 三个存储迭代器 → id 空间侵入式双向链 ----
    basic_prev: OpId, basic_next: OpId,     // 块内 op 序(std::list<PcodeOp*> op)
    ins_prev: OpId, ins_next: OpId,         // alive 或 dead 表(alive/dead 二选一,由 dead flag 分)
    code_prev: OpId, code_next: OpId,       // storelist/loadlist/returnlist/useroplist 之一
}

pub struct IdList { head: OpId, tail: OpId, len: u32 }   // 哨兵 id=0 保留槽(= std::list end())

pub struct OpArena {
    slots: Vec<OpSlot>, gens: Vec<u32>, free_head: Option<u32>,
    optree: BTreeMap<SeqNumKey, OpId>,   // op.hh:280 map<SeqNum,PcodeOp*>(OPTREE 道已证键化恒等)
    deadlist: IdList, alivelist: IdList, // op.hh:291-292
    storelist: IdList, loadlist: IdList, // :293-294
    returnlist: IdList, useroplist: IdList, // :295-296
    deadandgone: IdList,                 // :297(destroy 保持槽占用=oracle "memory not reclaimed")
    uniqid: u64,                         // :298
}
```

**生命周期三层**(逐字对齐 op.cc):
- `create`(op.cc:941-948): 占槽 + `dead` flag + **deadlist 尾插** + optree 插入。
- `markAlive/markDead`(op.cc:1017-1034): **O(1) 链摘 + 目标表尾插**——id 链表手术,
  零扫描;VARMAPOPCREATE 的 pop 快速路径/retain 兜底**整体删除**(只剩唯一路径)。
- `insertAfterDead`(op.cc:1039+) / `moveSequenceDead`: 链表定点插入/区间 splice。
- `destroy`(op.cc:984-999): optree 擦除 + deadlist 摘 + codeList 摘 + **deadandgone 尾挂,
  槽保持 Occupied**(dangling 引用仍可读——iop 常量解析依赖此语义,见 §2.5)。
- `destroyDead` / `clear`: 遍历 deadlist→destroy;clear 才真释放槽(free-list 归还,gen++)。

**iop-space 编码**: 现状 `Arc::as_ptr` 编码进 iop 常量偏移(funcdata.rs:4745-4754,
`get_op_from_const` 解码回句柄)。id 形态 = **OpId 打包进偏移**。oracle 本来就是
`PcodeOp*` 强转 offset(op.hh:249 `getOpFromConst`),编码值**从不出现在 C 输出**
(iop 注释 varnode 的打印走 target 解析),故编码替换不可观测——但 W1 验收时必须审计
所有 iop 偏移消费者(printRaw/marshal/探针 dump)无裸偏移泄漏(§5 R3)。

### 1.3 VnArena — VarnodeBank 1:1 镜像(varnode.hh:365-374 / varnode.cc:25-80)

oracle VarnodeBank = **两棵排序树**(`VarnodeLocSet loc_tree` 按 loc 后 def,
`VarnodeDefSet def_tree` 按 def 后 loc,varnode.hh:52-55)+ uniq 计数器;
**没有 alive/dead 列表**(与 op 不同!)。Varnode 存两个树迭代器(varnode.hh:147-148
`lociter/defiter`)= O(1) 树擦除。

比较器逐字核验(varnode.cc:34-79):
- LocDef 键 = `(addr, size, flags&(input|written) 以 free-last 序, [written→defSeqNum | free→create_index])`
- DefLoc 键 = `(flags&(input|written) free-last, [written→defSeqNum], addr, size, [free→create_index])`

```rust
pub struct VnData {           // varnode.hh:135-156 逐字段
    flags: u32, size: i32, create_index: u32, mergegroup: i16, addlflags: u16,
    loc: Address,             // :140(POD)
    def: Option<OpId>,        // :143 PcodeOp*(Weak 消灭)
    high: Option<HighId>,     // :144(§3.2 HighVariable)
    mapentry: Option<SymbolEntryId>, type_: TypeRef,
    descend: Vec<OpId>,       // :149 list<PcodeOp*>(Weak 消灭;维护纪律见 §5 R4)
    cover: Option<Box<Cover>>, // :150 惰性
    temp: TempSlot,           // :151-154 union{Datatype*,ValueSet*} → 枚举
    consumed: u64, nzm: u64,  // :155-156
    // 存储迭代器等价物: 反规范化树键(在 oracle erase+reinsert 的同位点更新)
    loc_key: VarnodeLocKey, def_key: VarnodeDefKey,
}
pub struct VnArena {
    slots: Vec<VnSlot>, gens: Vec<u32>, free_head: Option<u32>,
    loc_tree: BTreeMap<VarnodeLocKey, VnId>,   // 键全 POD,比较零锁零解引用
    def_tree: BTreeMap<VarnodeDefKey, VnId>,
    uniqbase/uniqid/create_index: u64/u64/u32,
}
```

**关键点**:
- 比较器里 `a->getDef()->getSeqNum()` 的跨对象读(varnode.cc:52-53)被**键内反规范化**
  消灭: def SeqNum 的排序投影 = (addr,time)(address.hh:154-158,OPTREE 道已核不含
  order 字段)且创建后不可变 ⇒ 键在 `xref/setDef/setInput/makeFree` 同位点重算即可
  (这些正是 oracle 擦除+重插树节点的位点)。VARMAPOPCREATE 实测的 insert_free
  398,450 次/1.47s 锁序树下降(每次比较 2 锁)→ POD 键下降。
- `destroy`(varnode.cc:1250-1330 域) = 两树 remove(用槽内键副本,BTreeMap O(log n)
  与 oracle 存储迭代器 erase 同阶)+ 槽释放。
- beginLoc/beginDef 9 个重载族(varnode.hh:395-413)= BTreeMap range 查询,键构造同构。

### 1.4 BlockArena — FlowBlock/BlockGraph 1:1 镜像(block.hh:57-421)

oracle 形态: `FlowBlock` 基类(block.hh:119-132:`flags/parent/immed_dom/copymap/
index/visitcount/numdesc/vector<BlockEdge> intothis/outofthis`)+ 13 个子类型
(t_plain..t_infloop,block.hh:77-80 闭集)多态派发;`BlockGraph` 持
`vector<FlowBlock*> list`(block.hh:366)和工厂(newBlockBasic 等,block.hh:413-414)。
`BlockBasic` 另持块内 op 表 `list<PcodeOp*> op`(op 的 basiciter 定位)。

```rust
pub enum BlockKind {            // 闭集枚举 = 13 型 vtable 面;dispatch → match
    Basic(BlockBasicData),      // ops_head/ops_tail(侵入式 op 链)+ range + stopaddr
    Plain, Copy, Goto, MultiGoto, List, Condition, If, WhileDo, DoWhile,
    InfLoop, Switch, Graph(Vec<BlockId> 子件),
}
pub struct BlockData {          // block.hh:120-128 逐字段
    flags: u32,
    parent: Option<BlockId>, immed_dom: Option<BlockId>, copymap: Option<BlockId>,
    index: i32, visitcount: i32, numdesc: i32,
    intothis: Vec<BlockEdge>, outofthis: Vec<BlockEdge>,   // :127-128
    kind: BlockKind,
}
pub struct BlockGraph { blocks: Vec<BlockId>, /* start 等图级字段 */ }
// Funcdata { block_arena, bblocks: BlockGraph, sblocks: BlockGraph } —— 两个图共享一个 arena
```

**判决依据**:
- **enum 而非 trait 对象**: oracle 的类型集是闭集(13 型),所有 dispatch 点在库内;
  现状 `Arc<RwLock<dyn FlowBlock>>` 的 11 impl + 每访问 2 vtable(BLOCKSTRUCT 实测)
  换成枚举 match(判别数单分支/跳表)。BLOCKSTRUCT 已证 `get_out_ref` 引用化后仍剩
  ~110ns/试 miss 底(Arc 克隆+RwLock+vtable)——enum+id 后 miss 底 ≈ 一次 bounds check
  + 一次 match。
- **BlockBasic 的块内 op 表** = 侵入式 op 链的 head/tail(op.basic_prev/basic_next),
  精确复刻 oracle"op 存 basiciter"形态 ⇒ `opInsertBefore/After/Begin/End` 与
  `opUninsert` 全部 O(1) 链手术(oracle funcdata.cc 同构)。

### 1.5 BlockEdge 值化 — 无 edges arena(对照 oracle block.hh:57-65)

oracle `BlockEdge { uint4 label; FlowBlock *point; int4 reverse_index; }` 是**值类型**,
由源块 `vector<BlockEdge>` 拥有。Rust 镜像:

```rust
#[derive(Clone, Copy)]
pub struct BlockEdge { point: BlockId, flags: u32, reverse_index: i32 }   // 12B Copy
```

现状 `point: Arc<RwLock<dyn FlowBlock>>`(block.rs:3167)使每次 `get_out/get_in` 克隆
= 2 原子 RMW + pred RwLock + vtable——BLOCKSTRUCT 实测 53.4M 次 ≈3.78s。值化后
克隆 = 12 字节 memcpy(~1-2ns),**该地板 100% 消除**。`addEdge/removeEdge/switchEdge/
moveOutEdge/halfDelete*` 的 reverse_index 维护逻辑逐行保持(纯索引算术,无句柄语义变化)。

### 1.6 跨函数共享物(Architecture/Sleigh)— 保持 Arc 共享,arena 不跨界

oracle: `Architecture *glb` 是 Funcdata 对 Architecture 的**共享回指**;Architecture
是 LoadImage/Translate/SLEIGH/Database/TypeFactory/ProtoModel/TypeOp 表
`vector<TypeOp*> inst`/PrintLanguage 的**唯一属主**(architecture.hh:170-210 亲读)。
全部 Funcdata 共享一份,分析期(每函数)只读为主。

**判决**:
- `Funcdata.arch: Arc<Architecture>` **保持现状**(它已经是 Arc 共享而非 per-access 锁;
  正确形态)。arena **不进 Architecture**——TypeFactory/符号表/SLEIGH 图是跨函数共享,
  per-fd arena 反而破坏共享。
- W1 **不动 Architecture 的字段形态**(现有 `Arc<RwLock<TypeFactory>>` 等内部锁保留):
  136.6M 锁读热点(INSTERSECTCACHE)在 per-fd HighVariable/Varnode 面,不在 Architecture
  面;ACTIVEPARAM 的 getCallSpecs memo 已收口 29.57M→5.5M 步。
- W3(可选,独立票): TypeFactory 类型驻留化(TypeId+append-only arena,零锁驻留),
  SLEIGH 图物化 74ms 地板(SLEIGHSNAP 判定=分配器级/形态级问题,见其 §5-§6)——
  **本 campaign 预期零改善,诚实标注**。
- 并发论证(§5 R5): 每 Funcdata 单线程域(ACTIONLOOP/INTERSECTCACHE 的"每 Funcdata
  单线程"前提已在案;并行度=每函数一线程/一进程,examples 层),arena 是 Funcdata
  私有字段 ⇒ **零锁是构造性健全**,不是"碰巧没竞争"。

---

## §2 ② 索引类型与序语义

### 2.1 id 形态: typed newtype + 32 位代际

```rust
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct OpId  { idx: u32, gen: u32 }   // 8B = oracle 指针宽
pub struct VnId  { idx: u32, gen: u32 }
pub struct BlockId { idx: u32, gen: u32 }
pub struct HighId { idx: u32, gen: u32 }
```

- **typed**(非裸 usize): 编译期杜绝跨 arena 串用(block id 传给 op 表)。
- **gen 代际**: 槽复用(free-list)后 gen++ ⇒ 陈旧句柄 lookup 得 `None` 而非静默错对象。
  oracle 的对应物是"悬垂指针+守卫纪律"(op.cc:984-999 注释明言依赖 "in case pointer
  references still exist" 的保留);id+gen 把该纪律**机器化**。成本 4B/句柄,查找 =
  bounds check + gen 比较(分支可预测,~1-2ns)。
- **身份语义**(= oracle 指针判等): `Arc::ptr_eq`/`Weak::upgrade` 判等 → **id 相等**
  (idx+gen 全等)。地址复用造成的"伪同对象"在 oracle 属 UB 邻域(靠纪律避开),
  id+gen 形态下**构造性不存在**——严格更安全且与 oracle 守卫内行为一致。
- SeqNum/uniqid/create_index 计数器**原样保留**(oracle 的创建序标识,与槽索引无关)。

### 2.2 容器选型判决表

| 候选 | 判定 | 理由 |
|---|---|---|
| 手写 `Vec<slot>` + free-list + gen | **采纳** | ①迭代序永不暴露(所有迭代走 bank 链/树/图向量,slot 私有)⇒ 无 slotmap 的迭代序不确定性问题;②无新依赖;③生命周期三层(Alive/Dead/DeadAndGone/Free)自控,slotmap 无此概念;④~150 LOC |
| `slotmap` crate | 否决 | 迭代序不保证(我们不用其迭代,但引入依赖换不来决定性收益);代际句柄机制照抄其思想即可 |
| 裸 `Vec<T>` + index 无 gen | 否决 | 槽复用 ABA:destroy 后新建 op 复用槽,陈旧 inrefs/descend 句柄静默指向新对象——oracle 里这靠"先擦后毁"纪律防,纪律漏一处即静默错数据;gen 把它变显式 None |
| `generational-arena` crate | 否决 | 同 slotmap,且 intrusive 链需要自己写 |
| swap-remove 型(`Slab` 风格删除) | **禁止(红线)** | 破坏保序;见 §2.3 |

### 2.3 红线: 删除必须保 oracle 列表序,禁 swap-remove

**证据链**(VARMAPOPCREATE 已证): oracle markAlive/markDead = 存储迭代器 O(1) erase +
尾插,删除**保序**;Rugra 现在的 `retain` 兜底路径(非尾部删除)逐元素等价于 oracle
erase 结果序——**序保持是行为等价的前提**。任何 swap-remove 都会重排 alivelist/deadlist,
而这两条表的序是 beginOpAlive/beginOpDead 消费者(DeadCode/结构化/打印遍历)的可见输入。

**机制**: §1.2 的侵入式 id 双向链(哨兵槽 0)给出与 `std::list` **同构的操作集**:
`insert(end)/insert_after(node)/erase(node)/splice(range)` 全 O(1) 且保序;迭代 =
head→tail 沿 next 链。**同构操作 × 同一调用位点(逐函数 `// Ghidra:` 注释锚定)
⇒ 同一序**,不需要额外论证。

树侧: optree/loc_tree/def_tree 是 `BTreeMap<PODKey, Id>`,序 = 键全序 =
oracle 比较器投影的同一全序(OPTREE 道已对 optree 证过"键序=原 Ord 投影同一全序"
的恒等契约;varnode 侧用 varnode.cc:34-79 的投影逐字段重建,§1.3)。

### 2.4 迭代序恒等性论证(总结)

oracle 的每个可迭代结构都是**显式容器**(7 条 op 链表、2 棵 varnode 树、块向量、
descend 向量、HighVariable instances 向量),序由结构自身承载。arena 设计**逐一镜像
这些结构**(链→侵入式 id 链,树→BTreeMap<POD键>,向量→Vec<Id>),且在逐函数 1:1
移植的相同位点执行相同结构操作。归纳: 若初始态同构且每次操作保同构,则任意时刻
迭代序同构。**arena 的 Vec<slot> 物理顺序不进入任何 API**(slots 字段私有,代码评审
红线)——这是该论证成立的构造性前提,写入 W0 的 arena 模块文档头。

### 2.5 句柄语义特例清单(必须在 W1 逐项核销)

| 现状机制 | oracle 对应 | id 形态 | 风险 |
|---|---|---|---|
| iop 常量 `Arc::as_ptr` 编码(funcdata.rs:4745) | `PcodeOp*` 强转偏移(op.hh:249) | OpId 打包偏移;`get_op_from_const` 解包 | 编码值不出现在 C 输出;审计 marshal/printRaw/探针 dump 无裸偏移泄漏(R3) |
| `null_slot_sentinel` 单例(ptr_eq 模拟 NULL 槽) | `inrefs[i] == (Varnode*)0`(op.hh:166) | `inrefs: Vec<Option<VnId>>` | 胶水子系统整体删除;getSlot 语义 = 找 None |
| `Weak::upgrade` 失败当"不存在" | 悬垂指针+守卫 | 陈旧 gen → None | **不对称风险 R4**: descend 维护(eraseDescend 位点)必须逐条移植,不得依赖 Weak 失败代偿——oracle 的 descend 表在 op destroy 时被**显式擦除**,id 形态漏擦会留下可见陈旧条目(迭代序消费者!) |
| deadandgone 整 Arc 保留(op.rs:1776-1788 注释) | destroy 保持对象可读(op.cc:984-999) | 槽保持 Occupied-Dead 挂 deadandgone 链 | 同语义;clear() 才真释放;HTTPD-FULL-SEGV 事故背景下的保守面保持 |
| `Arc::as_ptr` memo 键(funcdata.rs:1774/2185/5040) | 指针身份键 | id 直接做键 | 纯内部 memo,行为不可观测 |

---

## §3 ③ 借用纪律 — "同一对象两个可变视图"怎么过借用检查器

### 3.1 主判决: `&mut Funcdata` god-object——因为 **oracle 本来就是**

**证据**(决定性,亲读):
- PcodeOp 的全部**结构性 setter 是 private + friend 限定**(op.hh:64-68:
  `friend class BlockBasic; // Just insert_before…` / `friend class Funcdata;` /
  `friend class PcodeOpBank;` / `friend class VarnodeBank; // Only uses setInput`;
  op.hh:133 注释 "Only used by Funcdata")。
- Funcdata 的公共 API 就是 god-object 形态: `opSetOutput/opSetInput/opUnlink/
  opInsertBefore/opInsertEnd/opDestroy/opSetAllInput/opRemoveInput/opInsertInput…`
  (funcdata.hh:444-527 亲读;Varnode 侧 `newVarnodeOut/setInputVarnode/deleteVarnode`
  同族)。
- 也就是说: **oracle 的全部交叉突变(op↔varnode↔block)本来就 100% 经 Funcdata 方法
  中转**。Rugra 现在的 `Arc<RwLock>` 形态才是偏离——每处 `op.write()` 对应的 oracle
  原文几乎都是 `fd->opXxx(...)`。

因此 id 化后的签名 `fd.op_set_input(op, Some(vn), slot)` **不是新设计,是 oracle 原形**;
借用检查器要求的"单一突变入口"恰好就是 oracle 的类边界。移植工作是把
`op.write().set_input(vn, slot)` 这类**散开的**锁形态收回到 god-object 方法内——
收拢位点=oracle 方法定义位,不需要发明。

### 3.2 模式清单(按侵入性升序,覆盖全部已知冲突形态)

| # | 模式 | 适用面 | 备注 |
|---|---|---|---|
| P1 | **纯字段读仍走 OpData/VnData 固有方法**: `fd.op(id).is_call()`、`fd.vn(id).flags()` | 大多数消费者(读:写 ≈ 10:1,12,050 调用点主体) | OpData/VnData 是纯数据+只读方法 ⇒ `&Funcdata` 即可;BLOCKSTRUCT 的 36M miss 路径=此形态(id 拷贝+bounds check+match) |
| P2 | **POD 快照拷贝**: 守卫密集循环先把 `OpCore {opcode,flags,start}` Copy 出来 | 规则池 per-try 守卫(OPPPOOL 形态) | oracle 同样缓存局部字段;12-24B 一次拷贝替代 5 次锁读 |
| P3 | **分域拆借**: `let (ops, vns) = (&mut fd.op_arena, &mut fd.vn_arena)` | op+varnode 同时突变(如 op_set_input: op.inrefs 写 + vn.descend push) | 三 arena 是不同字段 ⇒ 编译器免费支持;**这是 god-object 内部实现的主力模式** |
| P4 | **id-pair helper**: `fd.ops_mut2(a, b) -> (&mut OpData, &mut OpData)`(split_at_mut/双索引互斥断言) | 同域两对象同时突变(cseElimination 双 op、merge 配对、nodeJoin) | 少数位点;互斥断言 debug_assert |
| P5 | **读-改-写顺序化**: 先 `fd.op(a_id)` 读出决策,再 `fd.op_mut(b_id)` 写 | 现持两个 read guard 后一个 write 的位点 | 最常见重排;与 P2 常复合 |
| P6 | **算法对象持 id 不持引用**: TransformManager/TraceDAG/CloneBlockOps 等的成员句柄全换 id;需要 fd 的方法签名加 `fd: &mut Funcdata`(调用点本就有 fd) | transform.rs 全部(§3.4) | oracle TransformManager 持 `Funcdata&data`(transform.hh:637),形同 |

### 3.3 候选否决记录(逐案评估过)

| 候选 | 否决理由 |
|---|---|
| arena 槽内 `RefCell`/`UnsafeCell` 内部可变性 | 动态借用检查=RwLock 的线程局部廉价版,**同类税**(borrow flag 读改写+panic 代替阻塞);把编译期可查的别名错误变成运行期 panic;且掩埋 P3 的分域机会。只允许作为迁移期 debug 断言的临时形态 |
| GhostCell/qcell generativity | 编译期零成本但要求 brand 生命周期贯穿全管线(每个缓存句柄/Vec<句柄>/结构体成员),侵入性最大;与 oracle "句柄是可自由存储的值"形态冲突 |
| 代码级双形态桥接 `enum OpRef { Arc(…), Id(…) }` | 每个签名/每个调用点加一层 match;migration 面翻倍;且 Arc 分支不清零锁税,门禁数字失去"新形态"证明力。**分支级共存替代**(§4) |
| `Rc<RefCell<T>>` 线程局部引用计数 | 引用计数税仍在(非原子版);Send/Sync 边界与 examples 的每函数线程模型冲突;不如 id |

### 3.4 unsafe 消灭清单(实测口径: src 52 处 unsafe block/fn/impl,61 处裸提及)

| 文件 | 实测 | 类别 | 处置 |
|---|---|---|---|
| transform.rs | 9 处 unsafe(≈40 使用点) | **alias 类**(`*mut Funcdata` 字段 + `unsafe impl Send` + `&mut *` 造引用,transform.rs:676/1064/1086/1191…) | **W1 随 id 化消灭**: fd 按方法参数传(P6);句柄成员换 id;Send impl 删除(不再有裸指针穿越) |
| funcdata.rs:1774/2185/4745/5040 as_ptr | 4 处 | 编码/键类 | OpId 编码替代(§2.5) |
| float_emulate.rs | 3 处 | libc FFI(数学函数) | 换安全实现(core f32/f64 原生 + to_bits/from_bits;行为差需逐函数 oracle fixture 对拍——若 glibc 边角语义差,保守换 `libm` crate 或保留单点 FFI 并登记) |
| ffi.rs | 4 处 | FFI | 生产零 FFI 已核实(车道简报)⇒ `#[cfg(test)]`/feature 隔离 |
| compression.rs(25)/prefersplit.rs(11)/subflow/cover/blockaction/signature/sleigh_ffi(各 1) | ~41 处 | **数值重解释类**(bytes↔int 转换等,非 alias) | 逐处换安全 API(`from_ne_bytes` 族)或收拢为单一 audited helper;**与 alias 类区分**: alias 类是本 campaign 红线,数值类是卫生项(W2 收尾清点) |
| crates/kuna-sleigh(3) | 3 处 | 引擎内部(管理器别名) | 不在 campaign 写域(SLEIGH 镜像 C++ 形态,SLEIGHSNAP 判定保留) |

**目标态**: src/ 生产路径 unsafe = 0(alias 类)/数值类收敛到 ≤5 个带 SAFETY 论证的一行
helper 或 0;与"消灭裸指针 unsafe"的目标口径一致。

---

## §4 ④ 迁移序 — wave 划分与验收门禁

### 4.0 结构性事实(决定迁移形态)

- Rugra 反编译核心是**单 lib crate**(80 模块,src/ 305k LOC;crates/kuna-* 是 SLEIGH
  引擎独立 crate,不在翻转域)。类型是病毒式传染的:`PcodeOpRef` 改定义 ⇒ 全 crate
  必须同 commit 编译通过,**不存在"半个 crate 编译绿"的中间态**。
- 因此: **W0 spike 先行(纯新增,零集成)→ W1 在长寿命 lane 分支上做原子类型翻转**,
  分支不绿不合入;master 全程可发布(分支级共存,拒绝代码级桥接 D9)。
- W1 内部按依赖序转换文件(编译错误数是进度计),core API(§1 的 arena+god-object 面)
  在 W0 出口冻结,冻结后可多 lane 分 write-set 并行(AgENTS.md 铁律 6 租约纪律)。

### 4.1 Wave 表

| Wave | 内容 | 写域 | 车道数 | 出口门禁(全部亲跑) |
|---|---|---|---|---|
| **W0 spike** | `src/arena.rs` 新模块: OpId/VnId/BlockId/HighId newtype + slot 存储 + free-list/gen + IdList 侵入链 + BTreeMap 键类型 + **oracle 序语义单元测试**(markAlive/markDead/insertAfterDead/moveSequenceDead 重放 op.cc 序列;xref/setDef/makeFree 树键重放 varnode.cc 比较器投影)+ microbench(markDead 26.9µs→ns 级对照) | 纯新增 `src/arena.rs`(+`docs/api/arena.md`)+TODO_BOARD | 1 | ①单测全绿含序恒等;②microbench ≥1000× on retain 路径;③**设计复核 CR**(机制 C 形态:arena core 是全部核心算法的新地基);④API 冻结评审 |
| **W1 类型翻转**(原子,单分支 `/dev/shm/rugra-worktrees/arenaflip`,基=冻结点 master) | 按 DAG 序: (a) op.rs/varnode.rs/block.rs/funcdata.rs 容器+god-object API; (b) heritage/flow/frontend(创建路径先行,尽早暴露 API 缺口); (c) ruleaction(30k)/coreaction(23.7k)(规则池主力); (d) blockaction+tracedag+condexe; (e) varmap/merge/variable/cover/double_precis/prefersplit; (f) printc/prettyprint/printlanguage+长尾(comment/dynamic/paramid/fspec/jumptable/…); (g) transform.rs unsafe 消灭+float_emulate+ffi cfg+examples 接线 | (a)-(g) 分 write-set;串行依赖: b 依赖 a,c-f 依赖 a,API 补丁回灌 a | 5-7(a 冻结后 c/d/e/f 可并行;同一文件单 writer 铁律) | **硬红线(任何一条非恒等⇒停+二分,禁前推)**: ①canon curl `4ab1db2a`/httpd `7d5b9e7c` 双 md5 字节恒等(0/0/0·124/124+34/34); ②镜面五面=curl 13/httpd 2/vsh 0/sq 432/sqlite 845 全 PASS defects=numbering=0; ③sqlite 全语料 assembled cmp 字节恒等(1385/1385); ④VdbeExec --one 1055 GEN_MIRROR md5 `a067e05c` 恒等; ⑤`cargo test --lib` 1985P/0F/5I 数恒等(允许纯机械改写的测试同 commit 修,但**计数不得漂移**且 diff 逐条可归因为机械形态); ⑥bank 391/391; ⑦unsafe 清点(transform 归零/数值类清单化); ⑧机制 C CR(blockaction/varmap/merge/heritage 白名单逐 commit) |
| **W2 收获验证** | SPEEDPROF2 探针口径全套重测(逐动作比值表重画)+ 锁/克隆计数归零证明(grep .read()/.write() 于 src 核心 15 文件=0)+ 残差分票 + 数值 unsafe 卫生收尾 | profiling 只读+小额修复 | 1-2 | ①W1 全红线复跑;②逐动作比值表 vs SPEEDPROF2 §3 基线(每动作给出 Δ 与归因);③新票登记(未达 §7 预期的项逐项归因) |
| **W3(可选)** | Architecture 面: TypeFactory TypeId 驻留/callspec-jumptable arena/HighVariable 域终态微调;SLEIGHSNAP 分配器实验(SPEEDPROF-SNAP-ALLOCATOR-0001 既有候选) | 独立票,按 W2 数据决策 | 2-3 | 同 W1 红线子集+对应专项 |

### 4.2 迁移期风险调度(与在飞车道的关系)

- W1 翻转期间 master 的 blockaction/funcdata/op/varnode 等**热文件持续被镜面修复道
  改动** ⇒ rebase 成本真实存在。缓解: ①W1 基点选 MB 批收口后的平静窗;②每周定向
  rebase 热文件(冲突面=机械改写区,重放 codemod 即可);③翻转合入前冻结相关文件的
  新镜面票认领(root 调度),合入后旧票 rebase。
- 双形态**分支级**共存策略: master 一直可跑全部门禁(旧形态);arenaflip 分支在
  W1(g) 完成前不进任何 root 集成批次。回滚 = 弃分支(铁律 5 安全: master 未动)。

---

## §5 ⑤ 风险地图

| # | 风险 | 等级 | 机制/缓解 |
|---|---|---|---|
| R1 | **列表序分歧**(alive/dead/opcode 链 splice 位点移植错) | 高(对齐) | 侵入链与 std::list 同构(§2.3)+ 逐函数 Ghidra 注释锚定位点 + W0 序语义单测重放 + 可选: oracle OPACTION_DEBUG 事件流与 Rugra 探针逐事件对拍(仓库既有 drill 工具族) |
| R2 | **树比较器投影错**(loc/def 键漏字段/错序) | 高(对齐) | 键构造收敛为单一 `loc_key()/def_key()` 函数;W0 单测逐字段重放 varnode.cc:34-79;更新只允许在 oracle erase+reinsert 同位点(xref/setDef/setInput/makeFree)——位点清单在 W0 冻结 |
| R3 | **iop 偏移编码消费者泄漏**(marshal/printRaw/探针 dump 裸偏移) | 中 | W1 审计项: grep 全部 iop 空间偏移消费点;C 输出门禁字节恒等本身即最终捕获器 |
| R4 | **descend/维护纪律依赖 Weak 失败代偿**(不对称: oracle 显式擦除,Weak 形态漏擦不可见) | 中高(对齐) | id 形态漏擦=迭代序可见陈旧条目(更易暴露也更危险);W1 逐条移植 eraseDescend/addDescend/destroyDescend 位点;W0 加 descend 不变式 debug 断言(descend 中每个 OpId 可解析且其 inrefs 反指) |
| R5 | **并发面**(零锁健全性) | 低 | 构造性论证: arena=Funcdata 私有字段,Funcdata 线程 confined(examples 每函数一线程/子进程;ACTIONLOOP 顺序 perform 911 次在案;INTERSECTCACHE "每 Funcdata 单线程"前提既有);Architecture 共享面 W1 不动其锁形态 ⇒ 无新共享。W1 加 debug 断言样本运行(线程 id 记账)后移除 |
| R6 | **rebase/合并冲突**(W1 期间 master 热文件 churn) | 中 | §4.2 调度;codemod 可重放性使冲突重解成本可控 |
| R7 | **行为恒等门禁本身不充分**(字节恒等但语义漂移到"另一个同样字节恒等的形态") | 低 | 字节恒等是本仓最强门禁(五重);此外 bank 391/391 fixture 与 B2 逐函数门禁覆盖;W2 探针计数恒等(ops_visited/rule_tries/rule_hits/pool_passes 逐值)==ACTIONSTATS 口径(OPTREE 先例)作为行为旁证 |
| R8 | **借用冲突长尾**(P3-P5 覆盖不了的形状) | 中 | 预计集中在 merge/varmap/heritage(现持双 guard 位点最多);W1(c) 并行 lane 前先由 spike lane 把 ruleaction 前 3 个文件的冲突形态清单化,必要时增补 id-trio helper;禁止为绕冲突引入 RefCell(§3.3) |
| R9 | **回滚/事故** | 低 | 分支级共存;master 未动;铁律 5 |
| R10 | **人力/编译反馈**(12k 机械点,单 crate 翻转期无中间编译绿) | 中 | codemod(ast-grep 模式库,W1 前在 W0 末尾预演于 2 个文件)+ 每文件批后 `cargo check` 错误数单调下降作为进度计;W1 分支用 `/dev/shm/rugra-targets/arenaflip` 独立 CARGO_TARGET_DIR |
| R11 | **内存形态**(槽不复用则峰值=历史创建总数) | 低 | 采用 free-list 复用(gen 防 ABA);deadandgone 槽保持占用=oracle 同语义;VdbeExec 量级 ~120k 槽 × ~120B ≈ 14MB,无忧 |
| R12 | **W3 范围蔓延**(Architecture 面被顺手改) | 中 | W1 明确不动 Architecture 字段形态;W3 独立票按 W2 数据决策,防"重构无止境" |

---

## §6 ⑥ 工作量估算

**测量口径**(本设计实测): src 81 模块 304,964 LOC;含 RwLock 的文件 53;
`Arc<RwLock` 出现 1,595 处;`.read()/.write()` 调用点 12,050;`PcodeOpRef` 提及 1,353;
`Arc<RwLock<Varnode>>` 490;unsafe 52 处。

| Wave | 触达面(LOC,机械改写为主) | 新增代码 | 车道数 | 估算说明 |
|---|---|---|---|---|
| W0 | 0(纯新增) | ~1.5-2k(arena core+测试) | 1 | 一个标准车道体量;含序语义测试与 microbench |
| W1 | **~150k LOC / 15-18 文件**(funcdata 20.7k+ruleaction 30k+coreaction 23.7k+printc 22.6k+block 10.5k+blockaction 9.9k+heritage 8.3k+varmap 7.7k+merge 6.1k+varnode 5.5k+其余长尾~25k);12,050 调用点中预计 85-90% 可 codemod,10-15% 手改(借用冲突/双 guard 位点) | ~3-5k(god-object API+helper+不变式) | 5-7 并行 + 串行核心 | 本仓 lane 节奏下 = **2-5 个工作日的多车道协同**(比一个 MERGEBATCH wave 的总量略大);最大不确定项=借用冲突长尾(R8) |
| W2 | 只读 profiling+小额修复 | 报告 | 1-2 | 标准 |
| W3(可选) | Architecture 面 | 视票 | 2-3 | 独立立项 |
| **合计(不含 W3)** | — | — | **~8-11 车道 / 4 个 wave** | — |

CR(机制 C)负担: blockaction/varmap/merge/heritage 白名单 ⇒ W1 的 (c)(d)(e) 组每个
lane 交付需独立复核;按仓库现行 CR 车道节奏并行消化。

---

## §7 ⑦ 性能预期(对照实测地板,诚实标注不确定度)

### 7.1 地板逐项消除表(基线=五道终报实测)

| 地板(实测) | 量 | arena 形态 | 预期 |
|---|---|---|---|
| update_high 逐实例锁读扫描(INTERSECTCACHE) | 136.6M 锁读/2.54s(99.65% 空手) | id 字段读 | **100% 消除**(标志判剩余 0.24s 保持);merge 域 ~−2.5s |
| high_cover 深拷贝 35.2M 节点 | 0.37s | 已被借读收口(0.008s) | 保持 |
| BlockEdge 克隆(BLOCKSTRUCT) | 53.4M 次/~70ns=3.78s | 12B Copy ~1-2ns | **~−3.6s**(count_non_structural 3.78→~0.1s) |
| 规则 miss 底(get_block 克隆+锁+2 vtable) | ~110ns×36M≈2-3s(两道口径) | id 拷贝+enum match ~5-15ns | **−2~2.5s** |
| mark_dead O[n] retain(VARMAPOPCREATE) | 207,611×26.9µs=5.58s | O(1) 链手术 ~10-20ns | **~100% 消除**(−5.5s);pop 快速路径与 retain 兜底删除后唯一路径=oracle 原形 |
| 锁序树下降比较器(insert_free 等) | 398,450 次/1.47s+transition 0.53s | POD 键 BTreeMap | −1.5~1.8s(树操作本体 O(log n) 保持,oracle 同形) |
| optree/池派发残余(SPEEDPROF2) | 3.18s | 已 BTreeMap 化;残余=miss 重读 27.7M×RwLock+per-visit | −2.5~2.8s |
| Weak 升级(vn.def/descend) | 全库高频(未单列计) | id 直读 | 未单独测量,随动作域整体下降(计入动作级预期) |
| Arc 分配(vbank.allocate) | 468k×0.28µs=0.13s | 槽 push | −0.1s(小项) |
| SLEIGHSNAP 图物化 74ms/子 | 分配地板 ~50ns×1.5-2M | **不在范围**(Architecture 域) | **0 改善**(诚实);W3/分配器票独立评估 |

### 7.2 逐动作预期(SPEEDPROF2 §3 比值表对照,VdbeExec 单极)

| 动作 | 现值 | oracle | 现比值 | 预期值 | 预期比值 |
|---|---|---|---|---|---|
| blockstructure | 8.65s | 0.46s | 18.8× | **1.5-2.5s** | ~3-5× |
| heritage | 6.86s | 0.38s | 18.1× | **1.5-2.0s** | ~4-5× |
| markimplied | 4.40s | 0.23s | 19.1× | **2.5-3.0s** | ~11-13×(Cover 重建分配族=既有票 SPEEDPROF2-COVER-REBUILD-ALLOC-0001 协同,arena 只收句柄面) |
| oppool1 | 12.80s | ~3.3s | 6.4× | **5.5-7s** | ~2-2.5×(per-try 常数收 50-70%) |
| mergerequired | 5.33s | 1.44s | 3.7× | **~3.0s** | ~2×(算法本体占比更高,oracle 侧也 1.44s) |
| infertypes/deadcode(未钻道) | 4.63/3.55s | 0.61/0.91s | 7.6×/3.9× | 共渡 −2~3s(锁/vtable 面受益,归因未钻) | — |
| activeparam | 2.61s | 0.91s | 2.9× | ~2s | ~2× |

### 7.3 总量预期与不确定度

- **VdbeExec 单极: 45.92s → 预期 26-33s(中位 ~29s)= oracle 8.8s 的 3.0-3.7×**
  (现 5.2×)。构成法: 动作域合计现 ~40s,按 7.2 求和消 ~13-17s。
- **sqlite 全语料 --jobs 32 wall: 46.62s → 预期 ~31-36s**(wall 由 VdbeExec 尾界支配,
  FIXEDFLOOR 判定形态)。
- **不确定度声明(诚实)**:
  1. **±20-30%**: id 查找虽廉(bounds+gen ~1-2ns)但次数巨大(亿级);BTreeMap 仍是
     BTreeMap(oracle std::map 同阶);未钻动作(infertypes/deadcode)受益面只能粗估。
  2. **下界风险**: markimplied 的 Cover 重建分配族不受 arena 消除(算法本体+分配),
     若其占比高于估计,单极落点向 33s 端偏。
  3. **上界机会**: 布局局部性改善(槽连续 vs 逐 Arc 堆分配碎片)+ Weak 升级全免,
     可能优于中位。
  4. 上述全部为**预测**;W2 以 SPEEDPROF2 同口径探针重测为准,任何与预测的偏差逐项
     归因(门禁字节数恒等 ⇒ 语义不变,性能数字只影响后续票优先级)。
- **非目标重申**: SLEIGHSNAP per-child 0.11s 地板、canon golden 对拍、镜面残差行数
  (curl 13/sqlite 845 等)——**全部不在本 campaign 的变化面内**(字节恒等红线)。

---

## §8 红线汇总(本设计的不可妥协项)

1. **行为恒等是唯一完成判据**: canon 0/0/0 双 md5 字节恒等 + 镜面五面=钉值 +
   全语料 assembled cmp 恒等 + tests 计数恒等。任何非恒等 ⇒ 立即停、二分、归因,
   禁止"性能先拿到,差异以后对"。
2. **禁 swap-remove**;alive/dead/opcode 链 = 侵入式 id 链,只在 oracle 同构位点手术。
3. **arena 槽物理序不进任何 API**(slots 私有);一切迭代走镜像结构(链/树/图向量)。
4. **descend/inrefs 维护纪律逐条移植**,禁止依赖"陈旧句柄→None"代偿 oracle 的显式
   擦除语义。
5. **借用工具新增禁令**: 不引入 RefCell/UnsafeCell 槽内可变性与桥接 enum(§3.3);
   借用冲突只允许 P1-P6 模式与 id-pair/trio helper 解决。
6. **Architecture 字段形态 W1 冻结**;跨函数共享物保持 Arc 共享,arena 不跨界。
7. 每个被改写的映射函数保持 `// Ghidra: <file>:<line>` 注释锚点;W1 的机械改写
   commit 不宣称任何行为语义(措辞避开机制 A 红词,涉及语义收拢到 god-object 方法的
   commit 必须带 Alignment Evidence 四类语义核对)。
8. 本 campaign 的吞吐指标 = **红线全绿下的地板消除量(实测数字)**,不是 LOC/commit 数。

---

*设计: ARENADESIGN 车道(2026-09-30)。证据工件: /dev/shm/rugra-reports/
LANE_ARENADESIGN_2026-09-30.md;campaign 票组: docs/TODO_BOARD.md(PERF-ARENA-MIGRATION-0001)。*
