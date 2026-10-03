# `cover.rs` API Reference

**2026-08-23 修复（GETSTR-ZERODIFF-D）**: `rebuild_from_root_snapshot` 的 implied 输出遍历加 visited 集合（Arc 指针键）。Ghidra 的等价遍历（Cover::addRefPoint/addRefRecurse cover.cc:549-612）靠 cover 覆盖遏制递归——只扩展空/未覆盖区域，二次访问直接返回，implied 链不可能成环；Rudra 显式 worklist 无该信号，互读 implied varnode（X→Y→X）无限循环（my_fwrite/next_url 在参数 typelock 扩大同型合并组后实测 timeout）。


**状态**: 核心语义已对齐（two-piece 回绕 + 指针身份域）；Ghidra 12.0.4 对齐级别 L2（oracle fixture `COVER-TWOPIECE-RESIDUAL-0001` 全 13 case `MATCH`）
**源代码路径**: `src/cover.rs`

> 残留（order-only 限制族）：INDIRECT 端点的 `getOpFromConst` 目标 order 解析
> 仍回退到 INDIRECT 自身 SeqNum order（需 Funcdata op-bank 访问，登记于
> `COVER-TWOPIECE-RESIDUAL-0001` 后继）。

## 模块说明 (Module Doc)

Liveness cover for varnodes

Corresponds to Ghidra's `cover.hh`

## 表示法 (Representation)

Ghidra 的 `CoverBlock`（cover.hh:75-96）以两个 `const PcodeOp*` 存储区间边界，
含三个特殊编码：`(PcodeOp*)0`（块首，getUIndex→0）、`(PcodeOp*)1`（块尾，
getUIndex→`~0`）、`(PcodeOp*)2`（函数输入标记，getUIndex→0）。所有集合比较
走 `getUIndex` 投影（cover.cc:29-49），但 `empty()`/`boundary()`/`merge` 的
internal3/internal4、MULTIEQUAL-tip 判别还依赖**原始指针身份**。

Rudra 以 `CoverEndpoint` 枚举建模指针身份域，`CoverBlock::start`/`end`（pub
u32）缓存 `getUIndex` 投影。**当 `end < start` 且块非空时表示 two-piece 回绕
区间** `[start, ~0] ∪ [0, end]`（Ghidra merge 的 disjoint 分支 cover.cc:175-181
与 addRefPoint 的 not-contained `setEnd` cover.cc:587 产生）。

## 导出的公共 API (Public API)

### `pub enum CoverEndpoint`

CoverBlock 边界的指针身份域：

- `Begin` — Ghidra `(const PcodeOp *)0`，块首哨兵（`u_index() == 0`）
- `EndMark` — Ghidra `(const PcodeOp *)1`，块尾哨兵（`u_index() == u32::MAX`）
- `InputMark` — Ghidra `(const PcodeOp *)2`，函数输入标记（`u_index() == 0`）
- `Op { order: u32, multiequal: bool }` — 真实 PcodeOp 边界（`getUIndex` 投影
  域：普通 op 为 SeqNum order，MULTIEQUAL 折叠为 0 并保留 marker 身份）

#### `pub fn u_index(self) -> u32`

端点的 `getUIndex` 比较值（cover.cc:29-49 的投影）。

#### `pub fn from_op(op: &PcodeOp) -> Self`

从活动 PcodeOp 构造端点身份：MULTIEQUAL → order 0 + marker；INDIRECT → 被
守护 op 的 order（cover.cc:41-43，经 Iop 空间 input(1) 常量按 `Arc::as_ptr`
编码解码，与 `Funcdata::get_op_from_const` 同一 OPBANK-0001 契约；不可解析的
typed `call_spec` 注记回退自身 order）；普通 op → SeqNum order。

**2026-08-30 `LATTICE-GEN` 修复**：此前 INDIRECT 回退自身 order 是已登记残留，
main 的 mergeAddrTied 因此把「call-guard INDIRECT 定义新版 + 读旧版 + 被守护
call 的参数 trial 读」三个端点摊到不同 order 上，相邻 cover 块从 touch
（intersect==1，允许）变 overlap（intersect==2 → "Forced merge caused
intersection"，merge.cc:315）。映射到被守护 op 的 order 后三端点重合，
与 oracle 边界语义一致。

### `pub struct CoverBlock`

Range of P-code ops within a single basic block where a varnode is alive

Corresponds to Ghidra's `CoverBlock` class. `pub start`/`pub end` 为投影域
（观察层兼容），私有 `start_id`/`end_id` 为身份域；两者恒同步。

### `pub fn new() -> Self`

Create an empty cover block（Ghidra `start=0; stop=0;`）

### `pub fn clear(&mut self)`

Clear the cover block（指针级清空）

### `pub fn set_begin(&mut self, s: u32)` / `pub fn set_begin_id(&mut self, begin: CoverEndpoint)`

Reset start of range。忠实 `setBegin`（cover.hh:86-87）：若 stop 为块首哨兵
则提升为块尾哨兵（`if (stop==0) stop=1`）。

### `pub fn set_end(&mut self, e: u32)` / `pub fn set_end_id(&mut self, end: CoverEndpoint)`

Reset end of range（cover.hh:88）。

### `pub fn get_start_id(&self) -> CoverEndpoint` / `pub fn get_stop_id(&self) -> CoverEndpoint`

取边界身份（Ghidra `getStart`/`getStop`）。

### `pub fn set_all(&mut self)`

Mark the entire block as covered（`(Begin, EndMark)` → 投影 `(0, u32::MAX)`）。

### `pub fn empty(&self) -> bool`

指针级空判别 `(Begin, Begin)`（cover.hh:90-91）。two-piece（`end < start`）
**不是** empty——旧 order-only 模型把回绕误判为空是本修复的核心。

### `pub fn contain(&self, point: u32) -> bool`

点包含判定（cover.cc:107-120），含回绕分支
`upoint <= ustop || upoint >= ustart`。

### `pub fn boundary(&self, point: u32) -> i32`

边界刻画（cover.cc:129-142）：0 非边界 / 1 尾边界 / 2 定义点边界
（`start_id != Begin` 指针级判别，修复旧投影域误判）。

### `pub fn merge(&mut self, other: &CoverBlock)`

并集合并（cover.cc:147-184）：完整 internal1..4 判别（含
`op2.stop==EndMark`/`stop==EndMark` 身份判别）、setAll、disjoint 分支取较早
start 配另一区间 stop（可产生回绕）。

### `pub fn intersect_char(&self, op2: &CoverBlock) -> i32`

非破坏性交集刻画（cover.cc:59-102）四象限：one/one、one/two、two/one、
two/two。返回 0 无相交 / 1 仅边界接触 / 2 区间相交。

### `pub fn intersect(&mut self, other: &CoverBlock)`

RUDRA-GLUE：Rust 侧破坏性区间交助手（Ghidra 无此形态）；仅 one-piece 输入
在契约内。

### `pub fn get_u_index(op: &PcodeOp) -> u32`

活动 PcodeOp 的比较索引（`CoverEndpoint::from_op(op).u_index()`）。

### `pub struct Cover`

Full liveness cover of a varnode across multiple blocks

Corresponds to Ghidra's `Cover` class

#### `pub fn new() -> Self` / `pub fn clear(&mut self)`

空 cover 构造/清空（`BTreeMap<i32, CoverBlock>`）。

#### `pub fn get_cover_block(&self, i: i32) -> Option<&CoverBlock>`

取第 i 块的 CoverBlock（Ghidra 返回全局空块；Rust 返回 `Option`）。

#### `pub fn compare_to(&self, op2: &Cover) -> i32`

按首个覆盖块索引排序（cover.cc:223-247；空 cover 视作 1000000）。

#### `pub fn add_def_point(&mut self, block_idx: i32, point: u32)`

order 域便捷入口：置块为单定义点（`set_begin`+`set_end`，对应
addDefPoint 的 def 分支）。

#### `pub fn add_ref_point(&mut self, block_idx: i32, point: u32)`

order 域便捷入口：空块 `set_end(ref)`；否则 not-contained 时延伸 stop
（可能回绕）。无 CFG 递归（无块图访问）。

#### `pub fn contain(&self, block_idx: i32, point: u32) -> bool`

指定块上的点包含判定。

#### `pub fn contain_varnode_def_at(&self, is_input: bool, block_idx: i32, order: u32) -> i32`

Varnode 定义点包含刻画（cover.cc:441-462）：0/1/2/3。

#### `pub fn merge(&mut self, other: &Cover)`

逐块 `CoverBlock::merge`（cover.cc:465-472）。

#### `pub fn intersect(&mut self, other: &Cover)`

RUDRA-GLUE：破坏性集合交（无 Ghidra 对应）。

#### `pub fn intersects(&self, other: &Cover) -> bool`

非破坏性相交谓词（委托 two-piece 感知的 `intersect_char != 0`）。

#### `pub fn intersect_char(&self, op2: &Cover) -> i32`

非破坏性交集刻画（cover.cc:269-297）。

#### `pub fn intersect_list(&self, op2: &Cover, level: i32) -> Vec<i32>`

相交块索引列表（cover.cc:307-334）。

#### `pub fn intersect_by_block(&self, blk: i32, op2: &Cover) -> i32`

指定块上的交集刻画（cover.cc:392-406）。

#### `pub fn rebuild(&mut self, root: &Arc<RwLock<Varnode>>)`

按 def-use 链重建（cover.cc:477-496；implied 输出传递扩展）。

#### `pub fn add_ref_recurse(&mut self, bl: &Arc<RwLock<dyn FlowBlock + Send + Sync>>)` 与 `expand_roots`

递归回填前驱（cover.cc:524-558）：空块 setAll；非空块填底
（two-piece 保持回绕不填底）；精确 MULTIEQUAL-tip 判别
（`start_id == Begin` + 旧 stop 的 marker 身份）。`expand_roots` 为
BlockId 单栈迭代形（见 COVERREBUILD 节）;无 visited 集——重入帧
可证 no-op,处理即 oracle 字面递归行为。

**2026-09-29 性能重写（行为恒等, VDBEEXEC 残差⑤ mergerequired）**: oracle
本身即递归形态（cover.cc:535-536/551-552 `for(j..sizeIn) addRefRecurse(
bl->getIn(j))`）；Rudra 侧成本来自 DAG 边重入帧——每帧 FlowBlock 读锁 +
双 BTreeMap 查找,而重入帧全部是可证 no-op（每次可突变访问必留
`end == u32::MAX`——setAll 或填底 setEnd((PcodeOp\*)1),其余访问零突变;
二次进入时 `ustop != ~0` 与 `ustop == 0` 互斥,两守卫均不成立 → 既不突变
也不展开）。改为显式栈 DFS（前驱反压=精确升槽位 DFS 先序,访问序与 oracle
递归恒等）+ per-addRefPoint 入口的 `visited` 去重集（调用方全部直接
CoverBlock 突变先于首个递归帧,集不跨夹突变调用者共享）。`add_ref_point_full`
的 tip 循环与底部循环共用一个集合（同一 oracle 底循环的两臂）。

### `pub struct PcodeOpSet` / `pub trait PcodeOpSetImpl`

Ghidra `PcodeOpSet`（cover.hh:35-65）：懒 populate 的 PcodeOp 集合与
secondary affects 测试；`finalize` 按 (block index, SeqNum order) 排序。

**2026-09-29 帧常数收口（SPEEDPROF2 车道,行为恒等）**: `visited` 去重集
`HashSet<i32/usize>` → `FxHashSet`（rustc-hash 既有依赖;SipHash ~40-60ns/键
→ ~8ns;集合语义/探测结果不变——add_ref_recurse/add_ref_point_full 两处
tip+底部循环/rebuild_from_root_snapshot 四点）;`add_ref_recurse_expansion`
两处前驱下压（空块臂 + MULTIEQUAL-tip 臂,cover.cc:535-536/551-552 的
`for(j..sizeIn) addRefRecurse(bl->getIn(j))` 镜像）改为 `push_predecessors_onto`
——单读守卫内降槽位序直接压 `point` Arc（get_in_ref 免整 BlockEdge 克隆）,
推送序列与 `predecessors_of(...).into_iter().rev()` extend 逐项相同,省每
展开帧一个临时 Vec。重入 no-op 引理/访问序论证不变（上条）;VdbeExec
--one 1055 stdout 字节恒等,全语料 assembled 5,284,971B cmp 恒等。

## COVERREBUILD（2026-10-01）重建分配域 BlockId/视图化收口

**SPEEDPROF2-COVER-REBUILD-ALLOC-0001**: [COVPROF] 钻定 VdbeExec markimplied
构成（探针口径 ucl 5.93s,29,683 次脏重建 × 1.03M addRefPoint × 26.25M 展开
帧 @142ns/帧）: ①rc 展开 63%——每帧 FlowBlock 读锁+vtable `get_index`+Arc
clone/drop churn+`visited` FxHash 插入+per-根 Vec 分配（MULTIEQUAL 底臂
72 根/次=22.87M 调用）+BTreeMap entry;②rp 自身 32%——MULTIEQUAL 匹配槽
16.8M BlockEdge 克隆+expect_arc、双 map 查找。oracle 同构跑同一帧流
（~6ns/帧,全 L1 热指针操作,oracle markimplied 总量 0.175s=2.6% 份额）——
差距 100% 实现级（锁/vtable/句柄 churn,非算法）。四件恒等收口:

1. **`visited` 去重集整体移除**: 重入帧可证 no-op 引理（2026-09-29 已证——
   每可突变访问必留 `end==u32::MAX`,二次进入两守卫互斥不成立,既不突变
   也不展开）⇒ 处理重入帧=oracle 字面递归自身的行为,最终 Cover 不可区分。
   帧级实证: 移除前后帧流逐位恒等（26,254,274 帧/2,339,339 空臂/3,381,608
   推送,skip 1.3M→0 且不新增推送）。净省 26.25M 哈希插入+318k 集分配。
2. **`add_ref_recurse_expansion`/`push_predecessors_onto` → `expand_roots`/
   `push_predecessor_ids`（BlockId 栈形）**: 块以 `BlockId`（Copy）行栈,
   索引经 `BlockBankView::expect_index`（代际校验影子=guard 读同值,免锁/
   免 vtable）;句柄仅在需读入边的展开帧物化（`view.expect_arc`+单读守卫,
   2.66M/26.25M 帧）;前驱直接压 `edge.point` 值（零句柄克隆）。每
   addRefPoint 闭包一个 `bank.hold()` 视图+单栈。
3. **per-根调用合并为 per-闭包单栈**: MULTIEQUAL 底臂匹配槽根/tip 臂根/
   else 臂根全推入同一栈（反压=升序根序,每根子树先序完成=oracle
   for-j 逐根全 DFS 的精确栈等价）——22.87M per-根调用+Vec 分配 → 318k
   闭包调用;`matching_slots`→`get_in_ref` 直取 id（免 16.8M BlockEdge 克隆）。
4. **`add_ref_point_full` 单次 entry+scratch 线穿**: `blocks.get`+`entry`
   双查找并一（entry 后判 empty 同值——两查之间无突变）;`(index,bank)`
   单守卫并读;根/栈 scratch `Vec<BlockId>` 由 `rebuild_from_root_snapshot`
   持有跨 addRefPoint 复用（clear 保容,内容不跨调用存活）;签名加两
   scratch 参（merge.rs 三处冷路径调用点就地 `Vec::new()`——零容量零分配）。

行为恒等证明链: VdbeExec --one 1055 stdout md5 `15b47cf7` base==opt==交付
三态全等;sqlite 全语料 --jobs 32 assembled cmp 字节恒等——**车道口径勘误
（CR-COVERREBUILD §F.1/§G 跟进①,2026-10-01）**: 车道工件 5,285,218B/
md5 `15f545aa` 系 TYPE-WIRING-0001 之前的陈旧 Standalone 类型域二进制产物,
不可由任何忠实 658e57a9/0d137be0 构建复现（三重矛盾闭环见 CR 报告）,其
A/B 恒等结论仅在陈旧域内自洽;**权威口径 = 忠实双构建 A/B**（CR 亲证
0d137be0 与 658e57a9 各自忠实构建 assembled 逐字节恒等）+ **MB53 合并树
忠实重测新钉 5,279,330B/md5 `e96d2dc8`（--jobs 32 三轮字节稳定,1385/1385
ok）**,或以镜面 sqlite 面（对 oracle 真值 604/1385 恒等口径）为准;
canon curl/httpd md5 `b7773087`/`54f9b02c`==钉值+机制 B
0/0/0·124/124+34/34;镜面五面 curl 13·74/httpd 2·29/vsh 0·71/sq 324·810/
sqlite 706·1385 全 PASS 恰钉值;tests 2023P==基线。性能（**窗口限定口径,
CR §F.3/§G 跟进②校正**）: VdbeExec 单极 user **−2~−17% 窗口依赖**（车道
单窗 37.90→31.58s=−17%@load 23-37;CR 独立配对 −1.7%@load~90 分布不重叠;
方向多点独立证实）;全语料 wall **~−5%**（车道 −8.0%,CR 独立 −4.7%）;
探针口径 ucl 5.93→1.57s（rc 142→42ns/帧,块锁 28.59M→2.66M）。


## ARENAFLIP-e（2026-09-30）BlockEdge.point 值化翻转表示层变更

**PERF-ARENA-FLIP-0001 (e) 段**: `BlockEdge.point` 由 `Arc<RwLock<dyn FlowBlock>>`
翻转为 `BlockId`（oracle block.hh:57-65 的 12B 值形态,Copy struct;`point_id`
孪生字段并入 `point`）。本模块的消费位点已随迁:对端解析经**属主 bank**
（每块 `Weak` owner-bank 回指,`BlockBank::{expect_arc,expect_index,arc_of,
index_of,btype_of}` + `BlockBankView` 同形）;`Arc::ptr_eq(&e.point, x)` 改为
id 相等（同 bank 域内）;`e.point.clone()` 改为 `bank.expect_arc(e.point)`。
行为恒等证明链: canon curl `4ab1db2a`+httpd `7d5b9e7c` 字节恒等 +
tests 2018P（细节见车道终报与 commit 7f1d71b4.. 的 Alignment Evidence）。

## BLOCKFLIPW3（2026-10-01）批 3——前驱扫迁边影子

`push_predecessor_ids`（addRefRecurse 迭代展开的栈形, oracle
cover.cc:535-536 `for(j=0;j<bl->sizeIn();++j) addRefRecurse(bl->getIn(j))`）
改 `BlockBankView::with_in_edges` 单锁批量读：in-向量镜像按 DESCENDING
槽序 push 前驱 id（== 旧句柄守卫形态的同一 BlockId 序列），零句柄克隆/
零 peer 锁/零 vtable（block.hh:304 非虚 inline 读形态, wave 3 边影子）。

## MARKIMPLIED2（2026-10-02）重建热径块索引翻转——瞬态稠密 scratch 表 + 拷出

**PERF-COVER-REBUILD-DENSE-0001**: `Cover::rebuild`（cover.cc:477-496）的
26.25M 帧重建热径（`cover[bl->getIndex()]` operator[] 序列, cover.cc:530/573）
从每-Cover 的 `BTreeMap<i32,CoverBlock>` 查找翻转为**线程局部瞬态稠密
scratch 表**（`RebuildScratch`: `Vec<Option<CoverBlock>>` 按块索引直取,
负索引防御侧表 + `slots_clean` 拷出后免清零标记）+ 重建尾**拷出**回持久
BTreeMap（升序插入=同键同值同在场集,含 empty-present 项——oracle
operator[] 默认插入语义逐键保留）。要点:

- **`CoverWriteTable` 双实例化**: `entry_or_default`/`clear_table` 两臂
  （持久 BTreeMap 臂=冷入口 `add_ref_recurse`/merge.rs 单读 cover 路径;
  稠密 scratch 臂=重建热径）。核心 `add_def_point_tbl`/`add_ref_point_tbl`/
  `expand_roots_tbl` 泛型共享同一算法,守卫序逐条不变。
- **内存形态裁定**: 探针实测 cov_live_hwm=54,432 活 Cover、平均 46.3 项/
  重建 vs 稠密长 731.6——**每-Cover 稠密表不可行**（~0.5-1.1GB）;瞬态
  单表（~1,163 槽×28B/线程）+ 拷出（~46 次插入/重建）为 EdgeShadow 模板
  （id 索引/影子表/choke 拷出）的 cover 域承接。
- **(id, index) 栈帧对**: 展开帧压栈时一次解析块索引（bank 影子
  `expect_index`, 3.38M 次）,26.25M 弹帧免逐帧解析（无发布前提=既有
  expand_roots 支柱 3 的等值论证,注释就地记录）。
- **行为恒等**: 最终 map 态逐键逐值同前（rb_len_sum 1,372,916 逐位恒等）;
  读 API/Display/clone/PartialEq 面 BTreeMap 表示零变化,merge.rs 零改动。
  证明链: VdbeExec --one 1055 md5 **15b47cf7** base==opt==交付三态 +
  corpus assembled **29f54d21/5,280,272B** 逐字节恒等 + canon 双语素
  **b7773087/54f9b02c**==钉值 + 镜面五面恰钉值（详见车道终报）。
  机器检验: `test_cover_write_table_arm_equivalence`（cover.rs 测试模块）将
  同一 operator[]/clear 操作序列分别驱动两臂,断言 copy_out 后 map 逐键逐值
  相等（含 empty-present 键、负索引侧表、scratch 复用轮次零残留）——双臂
  等价性质的回归锁定。
- **性能**: 探针口径 ucl 2.04→0.97s、rc 62.7→13.6ns/帧（−78%）、
  markimplied 动作 2.81→1.88s;VdbeExec 单极 user 配对中位 −0.37~−0.39s
  （taskset 定核 3/5、5/6 对胜,负载 35-58 窗）;corpus wall 三交错对
  **−0.84~−0.95s**（37.42/34.64/34.75 → 36.57/33.69/33.91）。

## PERF3（2026-10-03）Vec 增长主簇——重建/走查暂存跨调用保留 + MULTIEQUAL 槽位容器移除

**PERF-ALLOCFLOOR-0001 session 3**: 画像（rbt execinfo 回溯,VdbeExec --one 1055）
钉死 Vec 增长主簇=realloc grow 的 **42.4%** 落在 `Cover::add_ref_point_tbl` 家族
（`expand_roots_tbl` 的 DFS 栈增长——每次入口全新 scratch Vec 的增长阶梯）。
oracle（cover.cc:477-496 rebuild / cc:565-612 addRefPoint / cc:524-558
addRefRecurse）在这些路径**零堆分配**（`path` 单栈向量 + C++ 调用栈递归）。
三处收敛:

- **`add_ref_point_tbl` 槽位快照容器移除**: 原 MULTIEQUAL `matching_slots`
  `filter_map collect`（增长阶梯,且在早退判定前无条件支付）→ cc:604-607
  原位形态——入口只快照 `num_input`,槽位测试平移到底部递归臂的逐槽短守卫
  循环（`op.get_in(slot)==root` → `rg.get_in_ref(slot)`,同升槽序,块守卫单次）。
  早退路径现在与 oracle 同零槽位扫描成本。
- **`RebuildScratch` 跨调用缓冲保留**: roots/stack/path/visited/descendants
  五缓冲并入既有线程局部 scratch（entry `mem::take` + 全出口 put-back,
  容量跨整个反编译存活）;`rebuild_worklist` 的每级 `root_descendants.clone()`
  与 `descend_iter().collect()` 改为 clear+extend 复用缓冲（cc:488 原位
  descend 走查的等值形——同内容同序）。每调用内容=全新 Vec 形（各缓冲调用
  内首用前 clear）,仅消除 Rust 增长 realloc 阶梯。
- **行为恒等**: VdbeExec --one 1055 双面 md5 恰钉值（canon **606dd8c0**/
  mirror **b3f5b487**,base==opt 逐字节 cmp 亲验）;双臂等价回归
  `test_cover_write_table_arm_equivalence` 保持绿（scratch 复用轮次零残留
  断言覆盖新缓冲域之外的表本体,新缓冲由字节恒等证明链覆盖）。
- **效果**（fast-release 同 profile A/B,base=git-archive 408f6827
  stale-guard digest be6cb02e 内容级验证）: realloc grow 2,354,170→
  843,433（cover+multicollapse 两簇出清后残量主剩 only_op_use
  [cc:1809 oracle 同为 reserve(64)+增长阶梯,形态相等]与 subflow 家族
  [cc:184-197 oracle 同为 emplace_back/push_back 阶梯,形态相等]——均
  oracle-form-equal,非偏离,不动）。
