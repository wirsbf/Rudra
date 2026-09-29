# `cover.rs` API Reference

**2026-08-23 修复（GETSTR-ZERODIFF-D）**: `rebuild_from_root_snapshot` 的 implied 输出遍历加 visited 集合（Arc 指针键）。Ghidra 的等价遍历（Cover::addRefPoint/addRefRecurse cover.cc:549-612）靠 cover 覆盖遏制递归——只扩展空/未覆盖区域，二次访问直接返回，implied 链不可能成环；Rugra 显式 worklist 无该信号，互读 implied varnode（X→Y→X）无限循环（my_fwrite/next_url 在参数 typelock 扩大同型合并组后实测 timeout）。


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

Rugra 以 `CoverEndpoint` 枚举建模指针身份域，`CoverBlock::start`/`end`（pub
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

RUGRA-GLUE：Rust 侧破坏性区间交助手（Ghidra 无此形态）；仅 one-piece 输入
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

RUGRA-GLUE：破坏性集合交（无 Ghidra 对应）。

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

#### `pub fn add_ref_recurse(&mut self, bl: &Arc<RwLock<dyn FlowBlock + Send + Sync>>)` 与 `add_ref_recurse_expansion`

递归回填前驱（cover.cc:524-558）：空块 setAll；非空块填底
（two-piece 保持回绕不填底）；精确 MULTIEQUAL-tip 判别
（`start_id == Begin` + 旧 stop 的 marker 身份）。

**2026-09-29 性能重写（行为恒等, VDBEEXEC 残差⑤ mergerequired）**: oracle
本身即递归形态（cover.cc:535-536/551-552 `for(j..sizeIn) addRefRecurse(
bl->getIn(j))`）；Rugra 侧成本来自 DAG 边重入帧——每帧 FlowBlock 读锁 +
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
