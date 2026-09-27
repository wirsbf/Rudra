# `merge.rs` API Reference

## 2026-09-26：StackAffectingOps 通道落地 + intersection 补 addrtied-vs-untied 分支（MIRATTR-F-RESIDE-0001）

`MergeTypeIntersectCache` 补齐 `HighIntersectTest::intersection` 的第二判定臂
（variable.cc:1186-1197）：cover 块交集为空且恰一侧 addrtied 时，经
`testUntiedCallIntersection`（variable.cc:1072-1083）判定 untied 变量是否跨过
可能影响 tied 存储的 CALL/受控 STORE。配套落地 `StackAffectingOps`
（merge.cc:63-89：populate=CALL 全集+有效 STORE guard；affectsTest=STORE 无
guard 即真/有 guard 按 isGuarded 地址段）与 `PcodeOpSet` 基座（cover.hh:36-70、
cover.cc:627-652：按 (块索引, SeqNum order) 排序 + blockStart + is_pop 惰性
populate）及 `Cover::intersect(const PcodeOpSet&, Varnode*)` 合并步进
（cover.cc:342-382，Rust 侧为 `cover_intersects_op_set` 自由函数——Cover 是
值类型且步进需缓存侧 op-set 状态）。通道字段（op_list/block_start/is_populated）
随整个 cache 经 attach/detach 往返持久挂载，等价 C++ 的 by-reference 成员
生命周期（merge.hh:85 + variable.hh:258）。`Merge::clear`/`MergePersistentState::clear`
按 merge.cc:1582 + cover.hh:63 清空；clear-lifecycle fixture 的
`channel_sizes_extended`/`fixture_deposit_channels` 改为委托 cache 字段（对外
签名不变）。`intersection` 及其上游（merge_required_result/merge_speculative/
merge_speculative_by_vn/merge_type_pair/merge_test_with_list/merge_range_must/
merge_linear）新增 `fd: &Funcdata` 参数以支撑惰性 populate 与 affectsTest 的
store-guard 查询。行为效应：curl 镜 my_get_line 38→6（F-RESIDE 族清零；余 6 行
=FORSPLIT+SEXT48 既有族），canon 双语料 301/862 零回退。

## 2026-09-22：VARGROUP-ABSORB-0001 车道探针剥离（无 API 变更）

剥离车道私有 `[DBG]` 诊断探针（wip 1cd9f682/d3755452 声明的临时探针清单含本文件），
源码恢复至车道 f7348207 状态（与 merge-base 36f26db3 同树）。探针结论已记录于
`docs/alignment_docs/VARGROUP_ABSORB_MECHANISM_2026-09-22.md`，无接口/语义变化。


## 2026-09-22：process_copy_trims 遍历序确定性（DETERM-COPYTRIM-0001 / DETERM-DOMINANTCOPY-0001）

AX 16 跑 9:7 双版本实证 + AZ 三函数 drill 同点（universal:dominantcopy
工作集逐进程漂移）：`process_copy_trims` 原实现用 ptr-keyed
`HashMap<usize,(Arc<HighVariable>,u32)>::into_iter()` 驱动 dominant COPY
的 `process_high_dominant_copy` 处理序——HashMap 迭代序为每 worker 进程
随机（RandomState 重播种），两个不同 HighVariable 的 dominant COPY 落同一
dom 块时插入序（SeqNum 相对顺序）逐进程随机，穿透到最终 C 输出语句序
（getparameter_constprop_0 的 `uVar32 = uVar27;` / `uVar27 = uVar25;`
A/B 互换，双 sha256 bimodal）。

修复（只改遍历确定性，不改语义）：镜像 `Merge::processCopyTrims`
（merge.cc:1418-1435）的首见序——遍历 `copy_trims` **列表序**，HighVariable
首次出现即 push 进 `first_seen` Vec（对应 cc:1423 `multiCopy.push_back` +
cc:1424 `setCopyIn1`），后续出现仅累加计数（cc:1427 `setCopyIn2`）；
`copy_trims.clear()` 移到两个循环之间（cc:1429 原位）；`first_seen` 序中
计数 ≥2 的 high 依次处理（cc:1430-1435 `hasCopyIn2()`）。HashMap 仅作
keyed 计数查找，不参与迭代（纪律同 merge.rs:2197-2209 SymbolNameTree 排序
模式）。Ghidra 侧 `ActionDominantCopy::apply`（coreaction.hh:1008）即
`data.getMerge().processCopyTrims()`，故 dominantcopy 域漂移与 AX locus
同源，一并消除。

验证：fast-release `curl_decompile` 12 连跑 stdout sha256 单值
（此前 9:7 双值）；差分门禁 defects=numbering=0 保持。

**状态**: 已核对（当前有效）  
**源代码路径**: `src/merge.rs`

## 2026-09-22：`gather_partial_pieces` 补 `PieceNode::isLeaf` 递归界(MERGE-GATHERPIECES-ISLEAF-0001)

Ghidra `PieceNode::gatherPieces`(op.cc:865-876)对每个 PIECE 输入先算
`isLeaf(rootVn,vn,offset-rootOffset)`(op.cc:801-817),只有非叶节点才递归。
isLeaf 的五项判定:(a) `vn->isMapped() && rootVn->getSymbolEntry() !=
vn->getSymbolEntry()`;(b) `!vn->isWritten()`;(c) `def->code() != CPUI_PIECE`;
(d) `vn->loneDescend() == null`;(e) addr-tied 时地址与 root+relOffset 对齐。
Rugra 移植只保留了 (c),非树形 PIECE 图(输入由读取它的同一 PIECE 定义)会
无限递归 —— FUNCDATA-OPSTACKLOAD-CONTAIN-0001 解锁 RuleLoadVarnode 后
curl `main` 在 ActionMergeRequired(groupPartials)确定性复现 256MB worker
栈溢出(worker-failure,main 从输出消失)。

修复:`piece_is_leaf`(op.cc:801 忠实移植,五项判定全补,符号项用
`Arc::ptr_eq` 对应指针相等;地址项同时比较空间与偏移)作为递归门;
`gather_partial_pieces` 增加 `root_offset` 参数并在非叶时才递归;
`group_partials` 候选来自 `MergePersistentState::proto_partial` 注册表(RulePieceStructure cc:7697-7698 与 SplitDatatype::buildOutConcats cc:2601-2602 经`register_proto_partial_root` 注册; merge.cc:967-976 按 `isDead`/`isPartialRoot` 过滤后逐 root 调 `groupPartialRoot`)。`group_partials` 按 `groupPartialRoot`(merge.cc:1381-1387)从 root 的
symbol entry 取 `base_offset`(无符号为 0),groupWith 偏移改为
`offset - base_offset`(cc:1404)。验证:main 恢复反编译(76/124,0
worker-failure),curl 全语料 defects=0/numbering=0。

**状态**: 已核对（当前有效）  
**源代码路径**: `src/merge.rs`

## 模块说明 (Module Doc)

High-level variable merging logic

Corresponds to Ghidra's `merge.hh`. This module is responsible for
merging multiple SSA Varnodes into a single HighVariable.

## 导出的公共 API (Public API)

### `pub struct Merge`

Manages the process of merging Varnodes into HighVariables

Corresponds to Ghidra's `Merge` class. Groups SSA varnodes that
represent the same logical variable into `HighVariable` instances,
then assigns human-readable names to each group.

### `pub fn new() -> Self`

Create a new Merge instance

### `pub fn clear(&mut self, fd: &mut Funcdata)`

Clear all existing HighVariables and reset merge state

### `fn live_varnode_set(fd: &Funcdata) -> HashSet<usize>` (private)

Liveness for merge. Builds the set of varnode Arc pointers that are still
referenced (as input or output) by any **alive** op — drawn from
`fd.obank.alivelist` plus block-level ops not marked DEAD. The result is
cached in `Merge::live_set` once per `merge_all` run and consulted by every
`loc_tree` traversal.

Why membership-in-alive-op-set, not `vn.def`/`vn.descend`: after
copy-propagation redirects `user.inrefs[slot]` to a new source, the old
varnode's `vn.def` still points at the now-marked-dead COPY op, and
`vn.descend` becomes empty — even though the varnode is still live (the
new consumer references it). So def/descend are unreliable post-optimization
signals; the only authoritative liveness source is "is this varnode in some
alive op's inrefs/output?". Input varnodes (function parameters) are always
live.

This is what makes `high.instances` authoritative when merge runs after
dead-code in the pipeline.

**Note (2026-07-02)**: `live_set` is now consulted only for cover computation.
`ensure_all_have_high` and `assign_names` no longer filter by it — they
iterate the full `loc_tree`, faithful to Ghidra's `Funcdata::setHighLevel`
(funcdata_varnode.cc:595) and `ActionNameVars::linkSymbols`
(coreaction.cc:2940-2976). The prior live_set filter left implied/CAST-output
and free Varnodes without a HighVariable name, forcing printc into the
`uVar_{offset}` fallback (341 placeholders in curl).

### `pub fn merge_all(&mut self, fd: &mut Funcdata)`

Perform the full merging + naming pipeline. Phase order:
1. `live_varnode_set` → cache authoritative live varnodes
2. `merge_addr_tied` → force exact-location runs inside maximal overlapping
   processor/spacebase clusters and form offset-aware `VariableGroup`s
3. `ensure_all_have_high` → singleton HighVariables for EVERY Varnode in
   `loc_tree` lacking one (faithful to `Funcdata::setHighLevel`,
   funcdata_varnode.cc:595 — no live_set filter)
4. `group_partials` → reconstruct marked PIECE/CONCAT trees in sorted
   PcodeOpTree order into offset-aware `VariableGroup`s (merge.cc:967-976,
   1374-1407), allowing
   structured pointer expressions to use the root HighVariable.
5. `compute_varnode_covers` → materialize per-Varnode liveness covers as the
   exact product of the oracle's lazy machinery: allocate via `calc_cover`
   (varnode.cc:254-263, the `Funcdata::setVarnodeProperties`/`assignHigh`
   call sites), force `COVERDIRTY`, then rebuild through
   `Varnode::update_cover_locked` → `Cover::rebuild` (cover.cc:477-496) —
   the backward fill from every read through CFG predecessors
   (`addRefPoint`/`addRefRecurse`, cover.cc:524-612) with MULTIEQUAL
   per-slot precision. Ghidra has no eager Merge pass here (covers rebuild
   lazily on first `getCover()`); eager materialization at this one pipeline
   point yields the identical state because `Cover::rebuild` is a pure
   function of def/descendants/CFG. The self-invented successor
   `[0,MAX]` propagator (`propagate_cover_through_cfg`) and its events-based
   predecessor (def/read blocks only, index-order live-out heuristic) are
   both removed; shape regression pinned by
   `test_compute_varnode_covers_backfills_intermediate_blocks`.

`protoPartial` ordering evidence: Ghidra registers roots from the ordered
`ActionPool::processOp` traversal (`action.cc:822`), and `groupPartials`
consumes that vector without sorting (`merge.cc:970-975`). Rugra's action
iterator advances the ordered `PcodeOpTree` (`action.rs:1400-1414`), and
`group_partials` consumes that same order. The HashSet only deduplicates root
identity after collection and cannot alter first-seen order. `groupWith` has
no duplicate/failure branch (`variable.cc:574-605`), so repeated offsets are
permitted and both-existing groups are combined unconditionally, matching
`combineGroups` at `variable.cc:599-604`; no duplicate error is synthesized.
Rust `VariableGroup::combine_groups` mirrors `variable.cc:74-89` by sorting
source pieces by `(group_offset,size)`, rewiring each piece's group, and
moving the complete source set before the source group is released.
The regression test
`test_compare_order_selects_strictly_earlier_op` asserts the -1/+1 polarity.
5. `merge_by_cover` → merge copy-related disjoint-cover pairs
6. `update_high_covers` → sync each HighVariable.cover from members
7. `assign_names` → Ghidra-style auto-naming

### `fn update_high_covers(&mut self, fd: &mut Funcdata)` (private, 2026-06-29; 2026-09-23 EM3 改走 updateCover 链)

Re-derive every HighVariable's cover by calling `update_high_cover(&ha)`
（variable.cc:338 `HighVariable::updateCover` 链：成员惰性重建 + piece 感知 +
内部 cover 重建），不再是裸 `update_internal_cover()`。Collects distinct
HighVariables reachable from loc_tree varnodes (deduped by Arc pointer). Must
run after all speculative merges finalize instance sets so high.cover reflects
all members. ActionMarkImplied (later in pipeline) consults high.cover.
（oracle 无此整体 pass——它经 `HighIntersectTest::updateHigh`
variable.cc:1148 与 `Varnode::getCover` varnode.hh:202 惰性维护;Rugra 因下游
直读存储 cover 而物化,达到同一不变量点。）

### `MergeTypeIntersectCache::update_high`（variable.cc:1148 HighIntersectTest::updateHigh,2026-09-23 EM3 终态）

脏判定从「仅 high 自身 coverdirty 标志」扩为「自身标志 OR 任一成员 Varnode 仍带
COVERDIRTY」——oracle 的 `Varnode::setFlags/clearFlags`（varnode.cc:352-374）在
写成员 coverdirty 时同步 `high->coverDirty()`，Rugra 的 varnode.rs 旗标写不传播，
此扫描在测试门补齐同一可观测状态（oracle 中两者同时置位，扫描命中的恰是 oracle
亦判脏的状态）。命中时经 `mark_high_cover_dirty` 补传播,再走
`update_high_cover`（成员惰性重建 + updateInternalCover 乘积）,最后
**无条件 `purge_high`**（variable.cc:1153-1154 逐字;EM2 曾实验「重建后内部
cover 逐位不变则跳过 purge」,但 blockIntersection 的判定是实例级 copy-shadow
对,不同实例分解可在同一 union cover 下给出不同判定,该门放行的陈旧缓存判定
产生错误合并(uStack_248/in_RDI 噪声),已移除）。piece 持有 high 保持仅标志判
（其新鲜度协议在 piece 机件 INTERSECTDIRTY/EXTENDCOVERDIRTY——`is_cover_dirty`
已含 extendcoverdirty;扫描+updateCover 路径在 EM2 实测不收敛,残余记
`MERGE-COPYNOISE-SPILLRESTORE-0001-R2`）。

### `fn gather_block_varnodes` / `test_block_intersection` 惰性读取 + 借用优化（2026-09-23 EM3）

两侧的 Varnode cover 读取前置 `Varnode::update_cover_locked`（oracle 的
`vn->getCover()` 惰性重建读,variable.cc:951/975/984 → varnode.hh:202）——
成员 pass 中途被标 COVERDIRTY 后不再喂陈旧 cover 给块级判定;piece-intersection
high（`interPiece->getHigh()`）不经 updateHigh 刷新,靠此重建对齐 oracle。
`block_intersection` 的 a/b cover 由 `intersection()` 一次物化并以引用下传
（原来每块重取 `high_cover` 深拷贝）；`test_block_intersection` 的成对判定借用
双方读锁（原 `cover.clone()` 每 (vn,other,block) 深拷贝 BTreeMap）。纯性能等价变换。

### `fn mark_high_cover_dirty(high)`（variable.hh:275 HighVariable::coverDirty,2026-09-23 EM3 新增）

`HighVariable::cover_dirty` 方法在持外层写锁调用时,其内部
`piece->markExtendCoverDirty` 的自腿（variable.cc:136 写回 own high）构成
**同线程同锁写重入死锁**——EM2 记录的「post-restart mergerequired 圈零进展锁
等待」的真因（gdb 显示线程 running 而非 blocked,与自旋/不收敛表象一致,实际是
写锁自等待）。本 helper 将「置 COVERDIRTY 标志」与「piece 走
mark_extend_cover_dirty_read」拆成两段独立锁窗口,可观测旗标状态与 oracle 内联
逐位相同。merge.rs 内所有补传播点（update_high / mark_implied /
compute_varnode_covers materialize 腿）一律走本 helper。

### `fn update_high_cover(high)` 调用点修复（2026-08-15，`COVER-REBUILD-SELFLOCK-0001`）

`update_high_cover` 对 high 自身 instances、piece Varnode 及相交
HighVariable 的 instances 逐个改调 `Varnode::update_cover_locked(&instance)`
（原来是 `instance.write().update_cover()`）。旧路径在持 root Varnode 写锁
的 `&mut self` 里再进入 `Cover::rebuild` 读取同一 Arc，遇到 MULTIEQUAL
slot 与 root 同一 Arc 的图（parseconfig 真实输入）即永久自锁；新入口由
`update_cover_locked` 在持锁窗口内快照 def/descend/implied 并以 Arc 身份
重建，不再重入。完整自锁拓扑（slot2 self-reference + 双槽读）由
`tests/oracle/cover_rebuild_1204.*` 行为门禁覆盖；`ActionMergeType`
caller 闭包与 cleanup 后动作顺序仍归 `PIPE-MERGETYPE-ORDER-0001`。

**2026-09-23（MERGE-COPYNOISE-SPILLRESTORE-0001 EM3）**：EM2 曾移除本函数的
逐成员 `update_cover_locked` 重建（当时归因于锁等待;真因见
`mark_high_cover_dirty`——嵌套写死锁,与成员重建无关),已恢复亲代全形
（own instances 重建 → 无 piece 则 `update_internal_cover`,否则 piece
updateIntersections + 相交 high 实例重建 + update_cover_read）。成员重建
腿即 oracle `updateInternalCover` 的 `inst[i]->getCover()` 惰性链
（variable.cc:331→varnode.hh:202）,Rugra 因 `update_internal_cover`
（variable.rs）直读 `cover` 字段而在此显式完成。

### `pub fn mark_implied(vn: &Arc<RwLock<Varnode>>)` (2026-06-29; 2026-09-23 EM3 补全)

Faithful to Merge::markImplied (merge.cc:1594-1605). Sets the IMPLIED flag,
then marks the **def op's inputs** `COVERDIRTY`（gated on `hasCover`,
merge.cc:1602-1603——它们的 cover 穿过现已 implied 的 root,任何后续读取前
必须重建）并经 `mark_high_cover_dirty` 补传播到各成员 high
（varnode.cc:358-359 setFlags 的传播半）。此前版本只置 IMPLIED 旗标、
靠 merge 周期整体重建兜底——pass 中途的 markimplied 判定因此吃到陈旧
成员 cover。Called by ActionMarkImplied when checkImpliedCover passes.

### `pub fn inflate_test(a: &Arc<RwLock<Varnode>>, high: &HighVariable) -> bool` (2026-06-29)

Faithful to Merge::inflateTest (merge.cc:1616). Tests if inflating varnode
`a`'s cover to cover `high` causes an intersection with a sibling instance
of a's own HighVariable (excluding `a` itself / its copy-shadow). Returns
true if there IS an intersection (varnode CANNOT be implied). The
authoritative check in ActionMarkImplied::checkImpliedCover.
**2026-09-23（VARGROUP-ABSORB-0001 §4-4）**: 全量对齐 merge.cc:1616-1646 三段——
①实例循环以 `Varnode::copyShadow`（COPY 链追踪，varnode.cc）放行同值影子、以
`intersect_char(...) == 2`（仅整区间相交；边界相触 == 1 放行）拒绝——原先的
`intersects()`（任意重叠含边界）把每个 SUBPIECE 字段件的 def 点（=输入影子的读点）
判成相交，是 30d6 域件无法 implied、以显式语句打印的直接原因；②补 `VariablePiece`
交集遍历（piece->updateIntersections + 逐相交件 `partialCopyShadow(a, off)` 放行
SUBPIECE/PIECE 派生影子）；③借用重构：实例快照先drop `ahigh` 读锁再进
update_intersections（其取 owning high 写锁——同线程读后写即死锁，曾致 markimplied
管线挂起）。

**2026-09-23（MERGE-COPYNOISE-SPILLRESTORE-0001 EM2/R2,EM3 终态）**: merge.cc:1621-1622 的
`testCache.updateHigh(high); const Cover &highCover(high->internalCover)` 落地为
「脏扫描（自身标志 OR 成员 COVERDIRTY）→ 命中才物化新乘积（成员
`update_cover_locked` 重建 + inst[0]->hasCover 门控合并），否则直读存储 cover」。
传播侧不可写：调用方（coreaction checkImpliedCover）全程持有该 high 的读锁，
成员重建的 clearFlags→high->coverDirty() 传播（varnode.cc:365-374）无法落锁,
靠 merge 周期起点的 `compute_varnode_covers` 全量重脏兜底（缓存门都在 merge 期内,
不会吃到跨周期陈旧 cover）。

**2026-09-25（CR 补丁）**: 陈旧前提清理——原注释「every intersection()/
update_high gate runs inside the merge passes, which start from
compute_varnode_covers' wholesale re-dirty」在 Action 序列管线中不成立
（compute_varnode_covers 仅遗留 merge_all 调用）；`high_cover()` 原始读取
helper 加警示头；update_high_covers 处对 checkImpliedCover 的依赖描述更正
（读 varnode cover + inflate 内现聚合）。剩余原始聚合读者可服陈旧 → 登记
`MERGE-HIGHCOVER-PROPAGATION-0001`（缺 varnode.cc:352-360 setFlags→
high->coverDirty 传播不变量的完整补齐）。

**2026-09-25（CANARY-EXPLICIT 级联）**: 上一段的「否则直读存储 cover」分支删除，
改为无条件从惰性重建的成员 cover 现聚合——Rugra 的变体路径没有完整维护
Ghidra 的「成员 cover 变脏必传播 high dirty」不变量（varnode.cc:352-360
setFlags → high->coverDirty，由 addDescend/eraseDescend/calcCover 触发），
重建后的成员 cover 留下「干净但陈旧」的高聚合：for-header 迭代临时件
（PTRADD/PTRSUB out）自身 cover 正确止于唯一 COPY 读点，陈旧聚合却到块底，
inflateTest 把边界相触（oracle 判 1 放行、保持 implied、canon 内联
`ppuVar12 = ppuVar12 + 1`）误判整区间相交（==2 拒绝）→ 循环体临时件显式化。
无条件现聚合=oracle 不变量下的恒等乘积，只比陈旧存储新。

## 2026-09-25：MERGE-HIGHCOVER-PROPAGATION-0001 收口（Lane HIGHCOV）

传播不变量的**突变半边**从读者侧补偿移回 oracle 位点：varnode.rs
`set_flags`/`clear_flags` 的 coverdirty 掩码臂、`add_descend`（cc:339）、
`erase_descend`（cc:325）、`calc_cover`（cc:261）现携带 varnode.cc:358-359/
371-372 的 `high->coverDirty()` 传播（实现=varnode.rs
`propagate_cover_dirty_to_high`，merge.rs `mark_high_cover_dirty` 委托同一函数，
单一实现）。传播体按 merge.rs 既有锁纪律序列化（high 写锁置位 → 释放 →
piece walk 的 own-high 末腿），全部调用点为语句级 vn 写守卫（无一跨 high
守卫存活，逐点核验 2026-09-25）。

**锁不可达的 clear 侧**（`update_cover_locked`/`get_cover` 的
clearFlags→coverDirty，varnode.cc:371-372——承载「attach 前已脏成员」角落）
维持不传播：调用方（checkImpliedCover 借用 `&HighVariable`、
`aggregate_high_cover_from`）持 high 读守卫，传播需同 high 写锁=重入死锁。
该缺口由三层防御吸收：①`HighVariable::new` 按 variable.cc:224 初始置脏
（新 high 首门必重建）；②`update_high` 的实例扫描保留（对 clear 侧缺口
精准检测：成员旗仍在扫描时可见）；③inflate_test/aggregate_high_cover_from
无条件现聚合。`high_cover()` 裸读者纪律不变：仅 intersection（update_high
后读=variable.cc:1170-1181 序）与 compare_high_by_block（merge_linear 排序前
逐 high 刷新=merge.cc:280-282 序）两个门内位点。

**hide_shadows 残余读者修复**：merge.cc:1087/1092 的
`vn->getCover()->containVarnodeDef` 是惰性重建读（varnode.hh:202）；Rugra
原裸读 `.cover`，同双循环内先行的 `op_set_input`（add_descend 置脏 vn2）后
即可服陈旧——现前置 `update_cover_locked`（与 gather_block_varnodes 同纪律）。

**flagsDirty 半边（CR-HIGHCOV 发现 1 修正，2026-09-25 二轮）**:varnode.rs
set_flags/clear_flags 现携带 varnode.cc:357/:370 的无条件 flagsDirty()
臂（variable.hh:164→FLAGSDIRTY|NAMEREPDIRTY，updateFlags 通道——存活读者=
merge_test_required/namevars/varmap/is_name_lock）；propagate helper 拆双臂
共享一次写锁；implied/explicit/addrforce/precis*/unaffected 访问器家族
（varnode.hh 经 setFlags 路由者）改走 set_flags/clear_flags；
mark_implied/compute_varnode_covers 的内联传播半边简化为字面 setFlags 调用
（merge.cc:1598/:1603 镜像）。锁纪律重验（261+32+4 处机械扫描零生产
共存面）；双语料 cmp 恒等重跑（见下）。

**验证**：curl/httpd 默认脸对亲父 a9475ecc **cmp 逐字节恒等**（577/0/0 ==
基线全指标）；httpd 双跑恒等；panic 0/timeout 3==基线（httpd）与 0/0（curl）；
cargo test --lib 1713P/1F（nonzeromask 预存）；bank 391/391；annotations/refs
--strict 绿；gcc 审计 104OK/20FAIL fail 名集==亲父。恒等判读：主路径此前的
读者侧补偿已覆盖全部活语料位点，本改动把不变量从逐读者补偿提升为结构化
维护（位点位点不再是唯一防线）。机制 C：merge 白名单——Cross-Review:
PENDING（CR-R2-GETPARAM 的登记先例与本收口同链；二轮窄域重审范围=
varnode.rs set_flags/clear_flags 及文档）。


### `pub fn merge_addr_tied(&mut self, fd: &mut Funcdata)`

Locked `Merge::mergeAddrTied`（`merge.cc:609-648`）入口。它按
`VarnodeLocSet` 的 location 顺序扫描，整空间只接受
`IPTR_PROCESSOR`/`IPTR_SPACEBASE`；每个地址段用
`VarnodeBank::overlapLoc`（`varnode.cc:1791-1820`）形成最大传递重叠簇，
并且每个精确 `(space,offset,size)` run 只读取第一个成员的 raw flags。
簇含 `ADDRTIED` 时先对整个重叠簇 `unifyAddress`，再按
input → written `SeqNum` 顺序以首个 High 为 survivor 强制合并每个精确
run，最后把不同 offset/size 的 High 以相对首地址的 offset 放入同一
`VariableGroup`。这不是简单的 `(Address,size)` 哈希分组。

`try_merge_addr_tied` 是 Result-bearing Rust 内核，保留当前覆盖路径上 locked
`mergeRangeMust`/`groupWith` 的错误文本，包括
`Cannot force merge of range`、`Forced merge caused intersection`、
`Duplicate VariablePiece` 和 speculative merge-class 错误。现有
`merge_addr_tied -> ()` Action 边界只能把 Err 转成 panic，异常类别仍与
C++ `LowlevelError` 不同，因此 production 边界明确为 **MISMATCH**，不得用
相同文本冒充完整异常通道 MATCH。

`AddrTiedLocRange` 的 gate flags 字段为 `head_flags`（自 `first_flags`
更名）：只记录每个精确 `(space,offset,size)` run **头成员**（`VarnodeLocSet`
顺序首位）的 flags。这是对 locked `overlapLoc`（`varnode.cc:1791-1820`）的
插桩验证结论：`:1798` 读首 run 头的 flags，`:1813` 只对**后续 run 的头**做
OR，而 `:1800/:1815` 的 `endLoc(size,addr,written)` 跳跃（`upper_bound` 于
`(addr,size,written,SeqNum(m_maximal))`）会越过同位置的**全部**后续成员——
同 run 的非头成员永不参与 gate。`merge_addr_tied_inner` 的 cluster 级
`head_flags` 折叠复现该跨 run 头联合（簇扩展条件
`next.offset <= running maxOff` 与 `:1804` 的延续条件一致）。
`tests/oracle/merge_overlaploc_1204.*`（runner
`tools/run_merge_overlaploc_oracle.sh`）双侧字节一致地钉住两个方向：
正例 cross-run 头联合门控（raw 头 + 重叠 run 的 addrtied 头 → run1 a+b
合并为 2-instance High、run2 c 独立），负例同位置后置成员不门控
（唯一 addrtied 成员非头 → 无合并，`hi=1, same=a~b=0`）；per-member OR
变体（把同 run 后续成员 flags 也 OR 进 gate）在负例上分歧（错误合并
`hi=2`），证明该 fixture 可鉴别该类回归。双侧 fixture 均在两个 case 之间
reset `rule_onceperfunc` 子 Action（C++ `Action::reset` / Rust
`ActionState::reset_for_function`），否则第二个 Funcdata 上的子 Action 全部
命中 `status_end` 短路（`action.cc:343-344/:352-356`），负例将退化为空转。

地址空间仍有一个表示层缺口：`Ram/Register/Overlay` 可确定为 PROCESSOR，
`Stack` 可确定为 SPACEBASE，locked `OtherSpace::INDEX == 1` 可确定为
PROCESSOR；`AddressSpace::Other(non-1)` 已丢失真实 `AddrSpace::getType()`，
实现选择 fail-closed。自定义 processor 或 spacebase（locked
`translate.cc:47-60` 允许任意 index 的多个 SpacebaseSpace）因而是源码已证明的
**MISMATCH**。

`tests/oracle/merge_addrtied_gates_1204.*` 使用真实双侧
`Funcdata/VarnodeBank/PcodeOp/HighVariable/VariablePiece/VariableGroup`
生产结构和 production `mergeAddrTied` 入口，投影 raw flags、输入/写入身份、
最大重叠簇、High 成员顺序、piece offset/size、group size/身份及 canonical
projected 成员、异常文本。C++ observer 从 tracked nodes 重建成员后按
`(offset,size)` 排序，而 Rust observer 读取实际 `group.pieces`；0/4/10 又恰按
升序插入，因此相等只证明该 projected order，不证明真实容器 comparator/迭代
顺序。门禁只决定性覆盖 register/ram/locked OTHER@index1/stack 进入，以及
unique/join 跳过；Overlay、Iop/Fspec、Const 等其余 variant 仍 **UNTESTED**。
其余覆盖包括首成员
ADDRTIED gate、mixed input/written 实例及其当前观察顺序、传递重叠及 0/4/10
mixed-size grouping、implied forced error。由于 input 恰在 written 之前创建，
且 written 的 `SeqNum` 与创建顺序同向，该 fixture 尚不能区分真正的
input→written→SeqNum comparator 与 creation-index 排序，故这一排序规则仍为
**UNTESTED**。此外未覆盖 duplicate piece、forced intersection、
neither-grouped speculative merge-class error 及 pre-existing piece group。
若已有一侧 grouped，旧 `merge_highs` 路径仍会在
`numMergeClasses != 1` 时记录后继续，而 locked Ghidra 会在 dirty
flags/symbol 与 piece-transfer 突变后抛 `LowlevelError`；这是源码已证明的
**MISMATCH**，并非单纯 fixture 缺口。若两侧都 grouped，旧路径仍是
debug-assert/release-false，同属 required-merge closure **MISMATCH**。
implied error 的 MATCH 也只限投影出的 payload、Varnode/High/group/topology；
High cover/type/nameRep/symbolOffset、Varnode mergegroup/cover/type/addlflags、
piece intersection/cover、group symbolOffset、Merge cache/copyTrims 与精确 op 边
仍未形成全状态闭包，记为 **UNTESTED**。该 error case 也在任何成功 exact-run
merge 之前即遇 IMPLIED，因而没有证明先发生部分突变后再抛错的 traversal timing。
传递重叠 case 证明了扩展与 `next.offset == maxOff + 1` 排除，但没有
`next.offset == maxOff` 输入，故 inclusive `<=` 边界仍 **UNTESTED**。
另一个刻意不合成的状态是 `opUninsert` 后的
dead-op/non-free written output：locked `mergeAddrTied` 本身确实没有 alive
过滤，但 `BlockVarnode::set` 会解引用已清空的 defining-op parent，说明它不在
该 Action 的合法调用前提内；Rust 同样不应在 merge 层自创 live_set 门。
因此只有列出的投影可判 MATCH，函数整体保持 MISMATCH/L2。

### `pub fn merge_test(&self, v1: &Varnode, v2: &Varnode) -> bool`

Test whether two varnodes can be merged into the same HighVariable.

Returns true if they share the same address space and size, and
neither is a constant or annotation (which should never be merged).

### `pub fn merge_force(&mut self, vn1: Arc<RwLock<Varnode>>, vn2: Arc<RwLock<Varnode>>)`

Force-merge two varnodes into the same HighVariable.

If vn1 already has a HighVariable, add vn2 to it (or vice versa).
If neither has one, create a new HighVariable for both.

### `pub fn assign_names(&mut self, fd: &mut Funcdata)`

Assign human-readable names to all HighVariables in the function.

Iterates every Varnode in `loc_tree` except constants and annotations
(faithful to `ActionNameVars::linkSymbols`, coreaction.cc:2940-2976).
Free Varnodes are named too — see the TODO in source: Ghidra skips `isFree()`
because its printc routes free Varnodes to `pushUnnamedLocation` (raw address),
but Rugra's printc still emits them (SSA-completeness gap), so they need a
name to avoid the `uVar_{offset}` fallback.

Naming follows Ghidra conventions:
- Stack negative offset → `local_Xh`
- Stack positive offset → `param_stack_Xh`
- Register → `uVarN`
- Unique temp → `uVarN`
- RAM global → `DAT_XXXXXXXX`

### `pub fn merge_adjacent(&mut self, fd: &mut Funcdata)`

当前实现覆盖 locked Ghidra 12.0.4 `Merge::mergeAdjacent`
（`merge.cc:983-1012`）的主循环：按 alive op 顺序对每个非 call op 的输出
尝试与其各输入合并。已覆盖门链：
`mergeTestBasic`（out/in）→ **`outputTypeLocal()==inputTypeLocal(i)` 类型门**
（:1001，`adjacent_local_types_match` 以 `LocalTypeKey` 规范等值 + 经
`factory_nochar_distinct` 比较 `get_base/get_base_no_char` 的实际 canonical
`Arc`）→ 尺寸相等 →
`mergeTestAdjacent`（:175-218 全守卫链）→ 非相交 cover 时推测合并
（`merge_speculative_by_vn(..., true)`，输出侧存活）。但 local-type 门仍是
上层 `LocalTypeKey` 模型，不是 Ghidra TypeFactory/TypeOp 返回的实际 canonical
对象身份；自定义 core 名称和多 non-char INT1 的 nochar 关系已闭合，Java
ZEXT、CPOOLREF/CALLOTHER/INDIRECT 等仍绑定
`TYPEOP-LOCALTYPE-DISPATCH-0001`。因此本函数保持 MISMATCH/L2。

### `pub fn merge_multi_entry(&mut self, fd: &mut Funcdata)`

对齐 locked Ghidra 12.0.4 `Merge::mergeMultiEntry`（`merge.cc:908-963`）。
按拥有 ≥2 个全尺寸 SymbolEntry 的 Symbol 重建分组（Rugra 从 Varnode 的
mapentry 反向指针重建；Symbol 按 SymbolNameTree 顺序 `(name, nameDedup)`
排序遍历，database.hh:366-370），对每个符号以 `mergeList[0]` 的 High 为
anchor：`testCache.updateHigh(anchor/newHigh)`（:930-935）→
`mergeTestRequired(anchor, newHigh)` 门（:936-941）失败时 `setMergeProblems`
（`dispflags |= merge_problems`，database.hh:240）+ `newHigh.setUnmerged()`
（variable.hh:168）+ `conflictCount`，continue → `merge(anchor, newHigh,
false)`（:942-947，anchor 存活）失败时同样标记；结束按 :950-961 的精确
warningHeader 文案报告（`Unable to[ fully] merge symbol: N[-- Some instance
varnodes not found.][-- Some merges are forbidden]`）。skipCount 在 Rust
重建中恒为 0（无 linked Varnode 的 SymbolEntry 上游不可见，无 ScopeLocal
multi-entry 注册表）。

### `pub fn merge_marker(&mut self, fd: &mut Funcdata)`

对齐 `Merge::mergeMarker`（merge.cc:889-902）：按 alive op 顺序遍历非
indirect-creation 的 marker op，INDIRECT → `merge_indirect`，MULTIEQUAL →
`merge_op`。

### `merge_indirect` / `snip_output_interference` / `collect_inputs`（私有）

对齐 `Merge::mergeIndirect`（merge.cc:846-882）全路径：`!isAddrForce` →
直接 `mergeOp`（:850-853）；否则先 `mergeTestRequired(out,in)` +
`merge(in_high, out_high, false)`（**输入侧存活**，:857，与 mergeOp 的
输出侧存活方向相反），失败后 `snip_output_interference`（:862；内部
`collect_inputs` 沿 previousOp-INDIRECT 链收集输出 high 的读
merge.cc:783-802，按 `PcodeOpNode::compareByHigh`（expression.hh:54，High
指针序）分组，每组一个 `allocate_copy_trim` snip COPY + 读重定向
:822-837），再试合并（:864-867）；最后兜底用 `allocate_copy_trim` 剪断
INDIRECT 本身（:871-877）并重合并，失败打 `[MERGE]` stderr 日志（Ghidra
:881 throw 的既定降级）。union 解析继承（:872-875 / :417-428）保守省略。

### `build_dominant_copy` 尾合并（私有）

对齐 merge.cc:1235-1237：`count > 0 && domCopyIsNew` 时直接执行
`HighVariable::merge(domHigh, NULL, true)` —— **null testCache**：无
`testCache.intersection` 预检、无 `moveIntersectTests`（Rust 直调
`merge_highs`，不经过 `merge_speculative`）；speculative 类语义由
`u.mergeGroup += numMergeClasses`（variable.cc:640-646）观察。

### `merge_highs` 的 (Some,Some) piece 臂（私有）

对齐说明：oracle variable.cc:699-711 对 speculative 抛 LowlevelError（经
`Merge::merge` 的常见 speculative 调用由 mergeTestAdjacent
（merge.cc:208-209）拒绝双 piece 候选；buildDominantCopy 直调传新分配、
无 piece 的 unique。非 speculative 则应走 `piece->mergeGroups` + 成对
`mergeInternal` + `markIntersectionDirty`。`merge_addr_tied` 现在会真实生产
piece/group，因此旧注释所称“全局不可达”已不成立：后续 required merge
若同时收到两个 grouped High，当前 `debug_assert!`/release `false` 仍与
oracle 不同，作为独立调用闭包缺口保持 **MISMATCH**，不在本切片窄投影的
MATCH 范围内。

### `wire_unique_high`（私有，RUGRA-GLUE）

Ghidra `Funcdata::newUnique` 立即为新 unique Varnode 调 `assignHigh`
（funcdata_varnode.cc:88-89）；Rugra `new_unique` 不分配 High，故
`allocate_copy_trim` 与 `build_dominant_copy` 的 dominant COPY 输出在此
补接（否则 :879/:766/:1236 的合并对 None High 静默 no-op、mergeOp phase-2
对 trim 输入过度剪枝）。funcdata.rs 侧 latent 缺口已登记 TODO。

### `pub fn merge_by_datatype(&mut self, fd: &mut Funcdata)`

对齐 locked Ghidra 12.0.4 `Merge::mergeByDatatype`（`merge.cc:359-401`）。
它按 `loc_tree` 顺序扫描完整生产范围，先排除 free 和
`mergeTestBasic` 不合格 Varnode，再用 HighVariable 的 mark 位稳定去重；mark
在分组前按收集顺序清除。分组只接受同一个 `Datatype *`（Rust 中为
`Arc::ptr_eq`），不会把结构相等但身份不同的类型合并。

每组由 `merge_linear` 执行 locked `merge.cc:272-292` 顺序：先更新所有
High Cover，按首个 Cover block、首实例完整存储地址、无定义优先、定义
p-code 地址四级排序；随后按 high-stack 插入顺序尝试第一个通过
`mergeTestSpeculative` 且 Cover 不相交的候选。

Cover 相交采用 `HighIntersectTest` 的双向缓存、block refinement、
copy-shadow/partial-copy-shadow 判定和成功合并后的缓存迁移。成功时第二个
HighVariable 的实例有序 drain 到第一个，merge-group、piece ownership、
Varnode→High 反向引用和最终 Cover 同步更新。该路径没有迭代次数上限、
提前退出或按规模近似。

函数接口目前固定为整个 `fd.vbank.loc_tree`，而 Ghidra 公共函数接受任意
`[startiter,enditer)` 子范围；因此完整接口行为仍记为 `MISMATCH`，本次
direct full-loc 函数投影单独做 oracle 门禁。当前 Rust `ActionMergeType::apply`
还会新建 `Merge` 并重跑 `merge_all`，而 locked Ghidra 持久使用
`data.getMerge()` 且只调用 `mergeByDatatype(beginLoc,endLoc)`；因此 Action
调用闭包及 cache 生命周期明确仍为 `MISMATCH`，不属于该 direct fixture 的
`MATCH` 声明。
`MERGE-DATATYPE-SCALE-0001` 的 locked same-input fixture 只把该 projection
中的 free 过滤规模、Basic 过滤、类型指针身份、跨空间/同存储稳定顺序、
merge-group、survivor/反向 High 引用与 mark 清理判为 `MATCH`。相交
block/copy-shadow/partial-shadow/piece、缓存迁移复用、speculative 各拒绝守卫、
Cover-block/null-def comparator 层级和大量 eligible High 的规模路径仍为
`UNTESTED`；它们不会因窄 projection 的零差分而升级。

### `pub struct BlockVarnode`

Represents a varnode within a specific block for merging purposes

 
### 2026-07-01：补全 Merge 9 步序列
merge_required(mergeAddrTied+groupPartials+mergeMarker)、merge_marker(MULTIEQUAL/INDIRECT IO 合并)、merge_copy(COPY 链 cover-guarded 合并)、merge_adjacent(同 op IO 推测合并)、merge_by_datatype(类型分组+线性合并)、hide_shadows(copy-shadow 分析)、copy_marker(internal COPY NONPRINTING 标记)。+merge_speculative 原语。merge_all 重排为完整 9 步。group_partials 已补齐 PIECE root 的有序重建与 VariableGroup 分组。

### 2026-07-01（续 2）：merge_multi_entry + dominant_copy
merge_multi_entry（merge.cc:908-963）：按 SymbolEntry Symbol 分组，多入口符号合并。dominant_copy（merge.cc:1415-1436）：COPY 链 cover-guarded 合并选主导。3 新测试。9 步 merge 全部实装（allocateCopyTrim 仍受缺失 union 基础设施限制）。

### 2026-07-03：命名对齐 Ghidra（camelCase→snake_case）
- `merge_linear_speculative` → `merge_linear`（对齐 `Merge::mergeLinear` merge.hh:110。原 Rust 名多出 `_speculative` 后缀，Ghidra 方法名无此后缀）。

### 2026-07-03（续）：命名对齐 Ghidra（camelCase→snake_case）
- `copy_marker` → `mark_internal_copies`（对齐 `Merge::markInternalCopies` merge.hh:1444）。

### 2026-07-03（续 2）：修正 Ghidra 引用行号
- `mark_internal_copies` 的 `// Ghidra:` 注释行号从 merge.hh:1444（实为 merge.cc 行号）修正为 merge.hh:134（声明所在）。

### 2026-07-04：merge_opcode/process_copy_trims 对齐 Ghidra（消除 3 个自创方法）
- `merge_copy` → `merge_opcode(fd, opc)`（对齐 `Merge::mergeOpcode` merge.cc:326）。签名改为通用 OpCode 参数；用 `merge_test_required`（新增，对齐 merge.cc:102-166）+ `merge_speculative`（cover 相交静默跳过，对齐 merge.cc:1565-1575）。删除原来的 `intersects_except_at` 豁免（Ghidra 无此豁免）。
- `dominant_copy` → `process_copy_trims`（对齐 `Merge::processCopyTrims` merge.cc:1415）。删除原自创的 cover-extent dominant 合并，改为忠实 no-op（copyTrims 列表为空）。剩余缺口：snip 子系统未移植。
- 删除 `merge_by_cover` + `merge_by_cover_single_pass`（无 Ghidra 对应的自创迭代补偿 pass）。
- 删除死代码 `merge_speculative_by_vn_except` + `merge_speculative_except`（原被 merge_copy/dominant_copy/merge_by_cover 调用，现已无调用者）。
- 删除 4 个基于自创行为的测试（test_merge_by_cover_*, test_dominant_copy_*, test_copy_marker_*）——它们的断言依赖 cover-except 豁免合并，与 Ghidra 的 cover-skip 语义冲突。
- merge_all 顺序对齐 Ghidra coreaction.cc:5717-5729（删 merge_by_cover，merge_copy→merge_opcode，dominant_copy→process_copy_trims）。

### 2026-07-04（续）：移植 snip/trim 子系统（copyTrims 填充链路）
移植 Ghidra merge.cc 的 forced-merge + snip 数据流改写子系统：
- `allocate_copy_trim`（merge.cc:411）：创建 COPY op + unique 输出，push 进 copy_trims。union 解析路径省略（无 union 基础设施）。**2026-09-24（PM-F2S）**：基础类型通道补齐——cc:416 `ct = inVn->getType()` → cc:429 `newUnique(inVn->getSize(),ct)` 无条件传递（不属于 union 省略范围）；trim COPY 输出现在经 `Funcdata::new_unique_typed` 携带输入 varnode 的数据类型。
- `snip_reads`（merge.cc:443）：截断一组读取到临时变量。INPUT 分支新 COPY 的
  SeqNum pc 取 block-0 `getStart()`（cc:456，2026-08-30 修正——原先传
  `Address::new(0)`，仅新 COPY 的 SeqNum 地址错，cover order 域不受影响）。
- `eliminate_intersect`（merge.cc:489）：检测单读 cover 相交并标记 snip（含 copy_shadow/partial_copy_shadow 检查）。
- `unify_address`（merge.cc:581）：对同地址组消除相交。
- `merge_addr_tied` 接入 unify_address（forced merge 前 snip，对齐 merge.cc:631-632）。
- `process_copy_trims` 改为遍历 copy_trims + 按 high 计数 + 清空（对齐 merge.cc:1420-1434）。dominant-copy 替换（processHighDominantCopy）待移植。
- 新增 Merge.copy_trims 字段（对齐 merge.hh:87）。
- 基础设施：BlockVarnode 完善（Ord/set/find_front）、varnode_def_loc/op_loc helpers。

## 2026-08-30：eliminate_intersect 单读 cover 全量构造（LATTICE-GEN 阻塞①）

`eliminate_intersect` 的单读 cover 从 order 域便捷入口
（`add_def_point`/`add_ref_point`，无 CFG 递归）改为 merge.cc:501-505 的
op-based 全量构造（`add_def_point_full` + `add_ref_point_full`）：

1. **CFG 递归**（cover.cc:565-612 addRefPoint / cover.cc:524-558 addRefRecurse）：
   INPUT varnode 的单读 cover 必须从 block-0 输入哨兵沿前驱回填到读点。
   旧实现只含读点所在块，中间块的 guard 定义永不 `contain_varnode_def`，
   oracle 会 snip 的读（glob_range INPUT marked=8）未 snip → mergeRangeMust
   panic（merge.cc:315）。
2. **marker-aware vn2 def order**（cover.cc:29-49 getUIndex）：MULTIEQUAL→0、
   INDIRECT→被守护 op 的 order（`fd.get_op_from_const` 解码）；旧
   `varnode_def_loc` 的裸 `get_seq_num().order` 两条规则都缺。

双侧证据（cpp-dbg oracle，CARRY_FAKE_NORET 补 noreturn 数据后）：glob_range
Ram/0x17660 组 23 成员 1:1（def/flags/desc 全同，INPUT marked 8=8）；
main Ram/0x17500 组 140 共享成员 desc/marked 全同，残余差异仅 `rep movsq`
pcode 提升差（INDIRECT+MULTIEQUAL@0x30d0 对）。curl E2E 0 panic（原
main/glob_range/next_url 3 panic）、defects 0/numbering 0。

配套（cover.rs）：`CoverEndpoint::from_op` 的 INDIRECT 端点改为解析被守护 op
的 order（原「回退自身 order」残留），使 call-guard 的新版定义端点与旧版
读取端点重合于 call order → 相邻 cover 块 touch 而非 overlap；
`add_def_point_full`/`add_ref_point_full` 转 `pub(crate)` 供 merge 调用。
`RUGRA_MERGE_DIAG` 诊断扩展（MERGE-PAIR：失败对实例 cover + 读者 order）。

## 2026-08-30：同域残留清理——aCover/range 两处切 _full 入口（R-LATTICE-CROSSREVIEW MINOR-4）

`build_dominant_copy` 的 aCover（merge.cc:1202-1207）与 `check_copy_pair` 的
range（merge.cc:1119-1121）仍用 order 域便捷入口构造，是上文单读 cover 改造
的同域残留。两处均切为 op-based 全量入口：

1. **aCover**：`add_def_point_full(domVn.def, is_input)` +
   逐读者 `add_ref_point_full(reader, outVn)`。补齐 endpoint 身份
   （MULTIEQUAL→order-0 marker、INDIRECT→被守护 op order）与 addRefPoint 的
   前驱回填——旧入口只标读点所在块，def 块与读点块之间的中间块完全缺失，
   `bCover.intersect_char(aCover)>1` 的相交计数可能偏低（漏标 → 多替换）。
2. **range**：`add_def_point_full(domOp.out.def, …)` +
   `add_ref_point_full(subOp, subOp.in(0))`；contain 查询点从裸
   `get_seq_num().order` 改为 `CoverBlock::get_u_index(&def)`（oracle
   `CoverBlock::contain(op)` 内部即走 getUIndex，cover.cc:107-120）——
   u_index 域一致性：INDIRECT def 的中间写入判定从此落在被守护 op 的
   order 上。
3. boundtype-2 的 `getSeqNum().getOrder()` 比较（merge.cc:536-538）保持裸
   order——oracle 该处即裸 `getOrder()`，非 u_index 域，勿改。

curl/httpd E2E 输出字节不变（见 w-lminors 报告），即语料上两处入口结果
一致；切换后构造域与查询域与 oracle 统一，消除未观测行为差。


### 2026-07-04（续 3）：完整移植 dominant-copy 替换子系统
- 移植 `process_high_dominant_copy`（merge.cc:1316）：对收到 ≥2 trim COPY 的 high，按同源 Varnode 分组，对每组调 build_dominant_copy。
- 移植 `find_all_into_copies`（merge.cc:1295）+ `compare_copy_by_in_varnode`（merge.cc:1045）：收集 high 的所有外来 COPY，按输入 Varnode + block index + order 排序。
- 移植 `build_dominant_copy`（merge.cc:1151）：支配树 LCA 选 dominant block（find_common_block_n），cover 检查可替换性（intersect_char>1），totalReplace+opDestroy 替换冗余 COPY。
- `process_copy_trims` 接入 process_high_dominant_copy（之前只计数，现在真正替换）。
- 移植 `merge_test_must`（merge.cc:241）+ 接入 merge_addr_tied（对齐 mergeRangeMust 的 mergeTestMust 门控）。
- 新增 `Cover::intersect_char`/`CoverBlock::intersect_char`（cover.cc:269/59）返回 0/1/2。
- 新增 `BlockGraph::find_common_block_n`（block.cc:796）N-way 支配树 LCA。
- 新增 `BlockBasic::get_stop_addr`（近似 block.cc:2328 getStop）。
- 新增 `Funcdata::op_insert_end`（funcdata.hh:461）+ `op_mark_non_printing`（funcdata.hh:519）。
- 新增 `Varnode::has_cover`（varnode.hh:284）。

### 2026-07-04（续 4）：hide_shadows 重写 + ActionHideShadow 委托
- `hide_shadows` 拆分为 `hide_shadows_of(fd, high) -> bool`（对齐 `Merge::hideShadows(high)` merge.cc:1070）+ `hide_shadows(fd)`（遍历所有 high）。
- `hide_shadows_of` 现在真正应用 opSetInput 重写（之前只分析不重写）。用 copy_shadow + cover.contain_varnode_def_at + op_set_input。
- `ActionHideShadow::apply` 从内联地址匹配逻辑改为委托 `Merge::hide_shadows_of(high)`（对齐 coreaction.cc:4831-4845 遍历 high + 调 hideShadows）。

### 2026-07-04（续 5）：移植 mergeOp per-op forced-merge 路径
移植 Ghidra mergeMarker 的 per-op forced-merge 子系统（merge.cc:656-902）：
- `trim_op_input`（merge.cc:692）：在 op 前插入 COPY trim（经 allocateCopyTrim → 填 copy_trims），替换 slot 输入。MULTIEQUAL 时 pc 取入边块的 getStop，插入到入边块末尾。
- `trim_op_output`（merge.cc:656）：把 op 输出移到 stubby unique，COPY 还原原输出。用原始 newOp（不填 copyTrims）。**2026-09-24（PM-F2S）**：cc:668/677 的 `ct = vn->getType()`（改线前读取）→ `newUnique(vn->getSize(),ct)` 类型通道补齐，stubby unique 携带原输出类型。
- `merge_op`（merge.cc:719）：三阶段 forced merge — 非cover限制 trim → cover 限制迭代 trim（trimOpInput/trimOpOutput）→ 真正 merge。
- `collect_inputs`（merge.cc:783）+ `snip_output_interference`（merge.cc:811）：INDIRECT 输出干扰检测 + snip。
- `merge_indirect`（merge.cc:846）：snipOutputInterference + mergeOp。
- `merge_test_with_list`（merge.cc:1657）：经 `type_test_cache.intersection`（HighIntersectTest port：intersectList(…,2) 候选块 + gather_block_varnodes/test_block_intersection 时间戳级判定 + 缓存/moveIntersectTests 生命周期）判定,与 Ghidra `testCache.intersection(a,high)` 同路径。曾用 aggregate_high_cover + intersect_char 粗近似（把同块字符重叠一律判相交,导致 mergeOp Phase 2 对时间戳不相交的 marker op 误入 trim 循环——sb-impliedfold lane 实测 main +8804 trim COPY vs oracle +45）,2026-09-22 sb-impliedfold 移除。
- `merge_marker` 从 merge_force 改为委托 merge_op/merge_indirect（对齐 merge.cc:889-902）。

### 2026-09-23（VARGROUP-ABSORB-0001 §4-4）：markInternalCopies 补 PIECE/SUBPIECE 两臂
移植 merge.cc:1478-1528（此前 "Omitted — no VariablePiece infrastructure"）：
- **PIECE 臂**（cc:1478-1506）：out/in0/in1 三个 high 都带 VariablePiece 且同组、偏移与拼接几何一致（LE：p3.off==p1.off 且 p2.off==p1.off+v3.size）→ `opMarkNonPrinting` + 双输入 `clearImplied+setExplicit`（内部重组 PIECE 隐藏，件以自身语句打印）。
- **SUBPIECE 臂**（cc:1508-1528）：out/in0 同组且 `p2.off + suboff == p1.off`（LE）→ 同样 nonprinting + in0 explicit。
main 的 0x30d6 梯：嵌套 4+4+16 重组 `CONCAT164/CONCAT204` 语句（43 处中间态的残余）经此隐藏，调用实参直接读 join。

### 2026-07-04（续 6）：移植 redundant-copy 标记子系统
移植 Ghidra markInternalCopies 的冗余 COPY 标记路径（merge.cc:1112-1367）：
- `shadowed_varnode`（merge.cc:1271）：判断 vn 是否被同 high 的另一个 instance 完全相交（intersect_char==2）。
- `check_copy_pair`（merge.cc:1112）：domBlock 支配 subBlock + 构造 range cover + 检查中间写入。
- `mark_redundant_copies`（merge.cc:1249）：从后往前对每个 subOp 找 domOp，checkCopyPair 通过则标记 nonprinting。
- `process_high_redundant_copy`（merge.cc:1345）：findAllIntoCopies(filterTemps=false) + 按同源分组 + markRedundantCopies。
- `mark_internal_copies` 重写为忠实 markInternalCopies（含 shadowedVarnode 无后代检查 + multi-copy 累积 + processHighRedundantCopy）。
<!-- annotation-pass: 2026-08-15 -->
 
 
 

### 2026-08-15：MERGE-PERSISTENT-STATE-0001 — Funcdata 持久 Merge 挂载
对齐 Ghidra 的 Merge 生命周期：`Merge covermerge` 是 Funcdata 的按值成员
（funcdata.hh:96），构造于 Funcdata 构造器（funcdata.cc:39 `covermerge(*this)`），
被所有 merge-family Action 经 `data.getMerge()`（funcdata.hh:440）共享，
仅在 `Funcdata::clear()`（funcdata.cc:108）时 `Merge::clear()`（merge.cc:1580-1587）。

- `MergePersistentState`（pub struct）：跨 Action 持久通道挂载——
  `test_cache`（merge.hh:86 HighIntersectTest）、`copy_trims`（merge.hh:87）、
  `live_set`（RUGRA-GLUE 存活前提，对应 Ghidra "vbank 只含存活 varnode"）。
  `clear()` 对齐 merge.cc:1580-1587；`channel_sizes()` 供 fixture 观测。
- `Merge::attach(&mut self, fd)` / `detach(&mut self, fd)`：Action 级入口在
  进入时从 `Funcdata::merge_state` 取回通道、退出时写回（coreaction.rs 每个
  apply 各建 `Merge::new()`，等价于 Ghidra 单一持久对象）。`attached` 守卫防止
  嵌套入口（merge_all → merge_addr_tied 等）中途二次往返。首次 attach 且
  live_set 为空时按当前 fd 重建存活前提。
- 接线入口（全部 attach/detach 包裹）：`merge_all`、`merge_addr_tied`、
  `merge_required`、`merge_marker`、`merge_multi_entry`、`merge_opcode`、
  `merge_adjacent`、`merge_by_datatype`、`hide_shadows_of`、`hide_shadows`、
  `process_copy_trims`、`mark_internal_copies`、`assign_names`。
- `merge_speculative` 重写为忠实 `Merge::merge`（merge.cc:1565-1575）：
  `testCache.intersection` 检查（惰性建 cover，variable.cc:1148-1156）→
  `move_intersect_tests`（variable.cc:681，HighVariable::merge 内）→ 吸收
  instances → `update_high_cover`（merge.cc:1572 `high1->updateCover()`）。
  原实现的 aggregate-cover 空前提（cover 未建时恒接受）被替换。
- `Merge::clear(fd)` 补 `live_set.clear()` + `fd.merge_state.clear()`。
- fixture：`tests/oracle/merge_persistent_1204.{cc,rs,metadata.json}` +
  `tools/run_merge_persistent_oracle.sh`（pinned base ec03e2f79136 +
  merge.rs overlay + funcdata.rs 四 hunk 确定性重建；8 行投影 6 行逐字节
  一致，2 行 MISMATCH 绑定 VARNODE-COPYSHADOW-ARC-0001）。

### 2026-08-16（复核 REWORK）：深度计数、门链、并集重建、点覆盖约定
复核 REJECT 修正（M1/M2）+ 吸收 `MERGE-HIGHCOVER-UNION-0001`：
- `attach_depth: u32` 替换 `attached: bool`——仅 0→1 时从 `Funcdata::merge_state`
  取回通道、仅 1→0 时回写；嵌套入口（merge_all → merge_marker 等）纯 no-op，
  精确镜像 Ghidra 单一持久对象（通道永在对象内，内层不可能"移出"）。修复
  merge_all 中途 detach 导致 compute_varnode_covers 读空 live_set 的回归。
- `merge_adjacent` 补全门链（merge.cc:996-1007）：`mergeTestAdjacent`
  （merge.cc:175-218，已有忠实 port 现接入循环）+ `outputTypeLocal ==
  inputTypeLocal` 类型门（:1001，经 `adjacent_local_types_match` 以比较族
  BOOL-out/INT-in 元类型规则实现，typeop.cc:925-1068 ctor 表；metain==metaout
  族与尺寸检查重合）。
- `merge_force` 三分支在吸收实例后置 HighVariable `COVERDIRTY`
  （variable.cc:660-663 mergeInternal 副作用）——后续 updateCover 重建并集
  cover；此前 survivor 保留单实例 cover 致相交判定用陈旧前提（tB 误并）。
- `compute_varnode_covers` def-no-read 约定修正：零读者=点 `[def,def]`，
  有更晚块读者=live-out `[def,MAX]`（对齐 oracle Cover::rebuild 编码；
  原无条件 MAX 与惰性重建路径不一致）。
- 测试前提修正（src/merge.rs tests）：single_entry 测试补 Ghidra 生产前提
  ——LOAD 指针输入为 spacebase（mergeTestBasic 拒绝，merge.cc:255-264）+
  entry 挂接先建 high 并置 SYMBOLDIRTY（variable.cc:421-432 才能看见）。
- fixture 新增 case_pipeline_tail（含 merge_all 生产入口）消除嵌套盲区；
  **13/13 行逐字节一致，overall=MATCH**（pinned base=e87ebfc5+overlay）。

### 2026-08-16（复核二轮 REWORK）：深度平衡、ctor 表类型门、吸收方向/类语义
复核二轮 REJECT 三项修正：
- **M1**：`hide_shadows_of` 的 singlelist≤1 早退前补 `self.detach(fd)`（与
  process_copy_trims 同型），堵住 merge_all→hide_shadows 每 high 泄漏 +1 导致
  通道永不回写的缺陷；`Merge::clear` 的 depth 重置改为 `debug_assert!` 平衡性
  断言（release 兜底保留）。fixture pipeline_tail 增加 Rust canary 断言
  （merge_all 后 `merge_state.channel_sizes()` live/cache 非空，无 stdout 影响）。
- **M2**：废弃 10-比较族黑名单，改为 `LocalTypeKey`（Base/BaseNoChar/TypeCode
  按 kind+metatype+size 规范等值）+ `local_meta_pair` 全 ctor 表（typeop.cc
  925-2566：含 CARRY/SCARRY/SBORROW/FLOAT_NAN/INT2FLOAT/TRUNC/POPCOUNT/
  LZCOUNT/INSERT/EXTRACT 等）+ 逐 slot override（shift slot1 getBaseNoChar、
  INSERT/EXTRACT slot0 UNKNOWN、INDIRECT slot1 TypeCode、PTRADD/PTRSUB 全 slot
  INT、CPOOLREF INT-in、CALLOTHER UNKNOWN 回退）。Java-mode 变体
  （selectJavaOperators typeop.cc:118-140）与 cpool/userop 记录类型登记 UNTESTED。
- **M3**：`merge_speculative` 增加 `isspeculative` 参数并按 merge.cc:1565-1575
  委托新共享吸收 `merge_highs`（variable.cc:675-712 全语义：piece 分派 +
  `merge_internal` + moved 实例重排 + vn.high 重指 + updateCover）；全部调用点
  按.oracle 方向/旗标校正——mergeOpcode(:346 out 存活/false)、mergeAdjacent
  (:1010 **out 存活**/true，修复原 in/out 倒置)、mergeMultiEntry(:943 anchor/
  false)、mergeOp(:766 out/false)、buildDominantCopy(true)。fixture 新增
  `groups=` 投影（varnode.hh:186 getMergeGroup）双侧逐字节观察存活方与
  speculative 类语义（mergeadjacent 后 P/Q1/Q2=1、tC=0 证明输出侧存活）。

### 2026-08-16（复核三轮窄面）：FLOAT_TRUNC 臂 + getBaseNoChar 等值语义
- `local_meta_pair`：FLOAT_TRUNC 移出 (Int,Int) 分组，单列 `(Int, Float)` 臂
  （typeop.cc:1913 `TypeOpFunc(t,CPUI_FLOAT_TRUNC,"TRUNC",TYPE_INT,TYPE_FLOAT)`，
  无 override → :1001 门拒绝同尺寸 float 输入）。
- `LocalTypeKey` 弃 derive(PartialEq)，手写等值：`getBaseNoChar(s,m)` 仅在
  `(s==1, TYPE_INT, type_nochar 已注册)` 时返回独立条目（type.cc:3619-3626），
  否则与 `getBase(s,m)` 同 canonical 指针——`BaseNoChar(Int,s)==Base(Int,s)
  for s!=1`；fixture 架构未注册 1 字节 INT（type.cc:3131/3220-3222）故 size-1
  也塌缩为同 base，生产 cspec 注册故保留 (Int,1) 区隔。两处注释同步更正。
- fixture 新增 `case_type_gate`（4 行）：INT_LEFT 移位量 size==输出≠1 通过门
  并在 mergeadjacent 合并（groups SH:1/TSH:0 输出侧存活）；FLOAT_TRUNC 同尺寸
  float 输入被拒。runner **17/17 overall=MATCH**。

### 2026-08-19（MERGE-PERSISTENT-STATE-0001 r2-M2 残差）：nochar 等值改为工厂注册态驱动
- 复核登记的两处 MISMATCH：FLOAT_TRUNC `(Int,Float)`（typeop.cc:1913）与
  `getBaseNoChar` 方向（type.cc:3619-3626）——两处在 HEAD 已正确；残余缺陷是
  `(Int,1)` 无条件视为不等。按源码：`getBaseNoChar(1,TYPE_INT)` 仅在
  `type_nochar` 已注册时返回独立条目（type.cc:3622-3623，cacheCoreTypes 自
  注册的 1 字节非 ASCII INT 核心类型填充，:3220-3221），且 `getBase(1,
  TYPE_INT)` 是 `typecache[1][INT]` 的 ASCII char（:3225-3229 优先覆盖；
  无 char 时单个非 ASCII int 自填 :3240-3242 → 两指针相同）。ASCII char 与
  non-char INT1 共存是产生不同指针的常见生产状态；多个 non-char INT1 也可能因
  typecache first-fill 与 type_nochar 后写产生不同身份。最终判定只能比较工厂实际
  canonical 对象，不能化约为名称或“是否同时存在某两类”的布尔规则。
- `LocalTypeKey` 弃手写 `PartialEq`，改为 `local_type_key_eq(a,b,
  nochar_distinct)`；`merge_adjacent` 每次 walk 经 `factory_nochar_distinct`
  读取 `fd.get_arch()→arch.types` 的实际 `get_base(1,INT)` 与
  `get_base_no_char(1,INT)` Arc 身份；无工厂 = type_nochar null 世界 → 相等。
- fixture 扩展三 case（12 行，runner 17→29）：`float_trunc_cast`（同尺寸
  cast 形 FLOAT_TRUNC + COPY 对照）、`char_gate_null`（无 1 字节 INT 核心类型
  → T1/SH1 与 4 字节对照 T4/SH4 同样合并，type.cc:3624 fallthrough）、
  `char_gate_char`（第二 FixtureArchitecture 以自定义名称注册 non-char/ASCII
  INT1 → T1/SH1 被拒、T4/SH4 仍合并；Rust 侧同样 clear→register custom
  names→cache 后挂 `fd.set_arch`）。runner **29/29 covered projection=MATCH**，
  整体仍为 **MISMATCH**。
- 单测新增 `local_type_key_eq` 双世界断言与 `factory_nochar_distinct`
  三态注册断言（仅回归；oracle 证据在 fixture）。
- 2026-08-20 独立复核 REJECT：`factory_nochar_distinct` 以固定名称
  `char`/`int1` 推断缓存身份，而 Ghidra `cacheCoreTypes` 按任意名称 core type
  的属性与 DatatypeSet 遍历更新实际 `type_nochar/typecache` 指针；另 Java ZEXT
  和 CPOOLREF local type 已可由源码证明分叉。修复必须下沉 TypeFactory/TypeOp，
  本节原“工厂状态驱动”仅对 fixture 的两个已测世界成立。
- r2 已关闭上述名称启发式：`a4a2fe9` 提供 canonical cache/nochar Arc，
  `factory_nochar_distinct` 直接 `Arc::ptr_eq`；fixture 使用
  `signed_byte_custom`/`ascii_glyph_custom` 仍保持投影一致。Java/CPOOL 与
  持久通道残差不变。
- 2026-08-23 (TYPEFACTORY-LEGACY-CALLER-MIGRATION-0001)：
  `factory_nochar_distinct` 迁移到 faithful `get_base_result`/
  `get_base_no_char_result`（Ghidra getBase/getBaseNoChar 为 non-const，
  type.cc:3619-3660，故取写锁）；oracle 的 LowlevelError（如未初始化
  alignment map，type.cc:3300-3302）在 merge walk 无法传播，按 throw 语义
  显式 panic 带上下文。reachable 状态（缓存命中/工厂注册态）输出与旧
  lenient twin 逐 Arc 等价；三态注册单测同步迁移。

### 2026-08-16（MERGE-PREEXISTING-GATES-0001）：五项预存在门/方向缺口
- `merge_indirect` 全路径重写（merge.cc:846-882）：isAddrForce 门、
  **输入侧存活**的 merge 尝试（:857/:865/:879，方向与 mergeOp 相反）、
  忠实 `collect_inputs`（previousOp-INDIRECT 链 + piece/group 匹配 +
  (op,slot) 对，merge.cc:783-802）与 `snip_output_interference`
  （compareByHigh 分组 + 每 High 一个 snip COPY + 读重定向，:811-839）、
  `allocate_copy_trim` 剪断 INDIRECT 兜底。旧行为（无条件 trim_op_output
  + mergeOp）删除。
- `build_dominant_copy` 尾合并改为 oracle :1236 的 null-testCache 直调
  （`merge_highs`，无 intersection 预检/moveIntersectTests），不再走带
  cache 的 `merge_speculative`；speculative 类由 mergeGroup=1 观察。
- `merge_multi_entry` 补 :936 mergeTestRequired 门 + setMergeProblems/
  setUnmerged + conflictCount/mergeCount + 精确 warningHeader 文案
  （:950-961）；Symbol 按 (name,nameDedup) 确定性排序遍历。
- `compare_just_loc`（variable.rs，配套 docs/api/variable.md 同步）补
  space 维：`Address::operator<` 全序（space 索引先于 offset，
  address.hh:375-393），跨空间重叠 offset 不再误序。
- `merge_highs` (Some,Some) piece 臂：debug_assert 钉 oracle 契约
  （variable.cc:699-711），release 保守跳过 + 如实注释（Ghidra 侧经
  Merge::merge 调用者不可达）。
- RUGRA-GLUE `wire_unique_high`：补 Ghidra newUnique 的 assignHigh 半边
  （funcdata_varnode.cc:89），修 trim unique 无 High 导致的静默 no-op 与
  mergeOp phase-2 过度剪枝（funcdata.rs latent 缺口另行登记）。
- fixture `merge_gates_1204`（4 case 14 行）+ runner：14/14 双侧字节一致
  （sha 9878946d…），merge_persistent_1204 复跑 17/17 不劣化（仅
  merge_rs_sha256 重 pin）。

### 2026-08-16：`Funcdata::linkSymbol` 忠实化（`FUNCDATA-LINKSYMBOL-TYPED-0001`）

`Merge::assignNames`（自创的 merge 期 per-High 命名，注解曾错指
merge.hh:83）删除：Ghidra 的 merge 序列（coreaction.cc:5718-5729）没有命
名步骤，Merge 也没有 assignNames。变量命名唯一来源是
`ActionNameVars::apply`（coreaction.cc:2978-3000）的符号驱动管线；死代码
`register_name` 表（错注 merge.hh:83 Merge::registerName）一并移除，其表
内容由 `ActionRestructureVarnode` 安装进 ScopeLocal.register_names。

### 2026-08-17：cover 端点 setter 化（`COVER-TWOPIECE-RESIDUAL-0001` 配套）

`compute_varnode_covers` 与（已禁用的）`propagate_cover_through_cfg` 中对
`CoverBlock::start/end` 的直接字段赋值改为 `set_begin/set_end/set_all`
调用：CoverBlock 引入指针身份域（`start_id/end_id`，对齐 Ghidra
`PcodeOp*` 哨兵语义）后，字段直写会破坏投影域与身份域的同步不变式。
区间值与语义零变化（详见 docs/api/cover.md 表示法一节）。

## 2026-08-23：MERGE-CLEAR-LIFECYCLE-0001 — 持久通道补齐与 clear 语义

- `MergePersistentState`（funcdata.hh:96 covermerge 挂载）补齐 Ghidra
  `Merge::clear`（merge.cc:1580-1587）清除的全部四个通道：
  新增 `proto_partial: Vec<PcodeOpRef>`（merge.hh:88，groupPartials 生产
  路径仍为 no-op，归 MERGE-PROTOPARTIAL-GROUP-0001）与
  `stack_affecting_ops`/`stack_affecting_populated`（merge.hh:85
  StackAffectingOps 的 opList/is_pop 镜像；`StackAffectingOps::populate`
  未移植）。`clear()` 现清 testCache/copyTrims/live_set(GLUE)/protoPartial/
  stackAffectingOps+is_pop 全部通道。
- 新增 RUGRA-GLUE fixture 观测/存入钩子：`channel_sizes_extended()` 与
  `fixture_deposit_test_cache()`/`fixture_deposit_channels()`（与既有
  `channel_sizes()` 同一前提：锁定 C++ fixture 经 #define private/class
  struct 直接读成员）。
- 观察投影：merge_clear_lifecycle_1204 双侧对拍中 merge 通道
  （testcache 2→0、copytrims 1→0、protopartial 1→0、stackops 1→0、
  stackpop 1→0）全部 MATCH；生产路径填充（intersection 真实缓存、
  groupPartials、StackAffectingOps::populate）保持 UNTESTED 登记。
- `fd.getMerge()` 持久化重构（Actions 直接共享单一 Merge 对象）仍归
  COREACTION-STATEFUL-MERGE-0001；本改动只覆盖其 clear 生命周期通道语义。
<!-- annotation-pass: 2026-08-23 -->

## 引用行号勘误（2026-08-23，root，legacymig 复核跟进）

merge.rs 两处 `type_nochar` 置空引用由 type.cc:3131 修正为 3128（clearCache 内；3131 是 charcache 循环行）。复核确认语义无误，仅引用偏移 3 行。

## 2026-08-23（VARIABLE-GETTYPE-LAZY-UPDATETYPE-0001 编译适配）：v_type 访问器改 TypeCell 域

HighVariable 的 `v_type` 缓存迁入 `TypeCell`（`RwLock<Arc<Datatype>>`，Ghidra `mutable Datatype *type` variable.hh:141 的 Rust 锁域，详见 docs/api/variable.md）。merge.rs 四处编译必需适配，语义不变：
- `:1141` `Arc::ptr_eq(&hi.v_type.get(), &ho.v_type.get())`（merge.cc:107-109 双锁类型等同检查，指针等同语义保持）
- `:1255` 同上（out/input 类型等同）
- `:3312` `first.read().v_type.get()`（updateType 后读缓存）
- `:3320` `Arc::ptr_eq(&datatype, &high.v_type.get())`

-  已降私有（R16 建议⑤）：残余调用均在同文件测试内，防再次误接为管线入口。


## 2026-08-29（DEBUGPROTO-DWARF-CHAR-0001 后续）：nochar 测试改用 raw 工厂构造无 char 注册态

`test_factory_nochar_distinct_registration_state` 的 `fd_int1_only` 世界原先依赖
`TypeFactory::new(8)` 只注册 `int1` 而无 ASCII char 的旧前提；DataOrg 引导现在经
`set_core_type_result("char",1,Int,true)` 镜像锁定 headless oracle 的 coretypes
供给（详见 docs/api/type_system/typefactory.md）。无 char 注册态改由
`TypeFactory::raw()`（type.cc:3106 空构造投影）+ 单条 `int1` 注册 +
`cache_core_types()` 显式构造：非 ASCII int 自填 typecache[1][INT] 并被选为
`type_nochar`（type.cc:3240-3242），`get_base(1,INT)` 与其同对象 → 判 NOT
distinct 的覆盖保持不变。仅测试构造方式变化，`factory_nochar_distinct` 生产语义零改动。

## RUGRA_MERGE_FREEVN_DIAG（worktree 临时诊断，非对齐面）

`RUGRA_MERGE_FREEVN_DIAG=1` 时，`allocate_copy_trim` 在接线前检测
「被剪输入为 free 且已有活 descendant」的 panic 前状态，向 stderr 转储
in_vn（地址/尺寸/flags/def/high）、每个活 desc op（opcode/地址/dead/
parent/inrefs 标 *THIS*）以及该地址全部触碰 op（读/写史）。
NONCONVERGE-GETPARAM-MATCHURL-0001 用它锁定终态：MULTIEQUAL slot-2
读 Stack/0x130 free vn（flags=COVERDIRTY、def=None、descs=1）。
镜像 Ghidra merge.cc:411 allocateCopyTrim 观察位；默认关闭，合入 root
前必须移除。

## 2026-08-29：eliminate_intersect boundtype==3 全量移植（GETPARAM-EMPTYELSE-0001 后续）

`Merge::eliminateIntersect` 的 boundtype==3（tail 交叉）分支从截断形态
（仅 `is_addr_force` 一道守卫，其余按"视为交叉"保守处理）补齐为
merge.cc:543-562 的完整五行守卫链：

1. `vn2.is_addr_force()`（cc:549，原有）；
2. `vn2.is_written()`（cc:550）；
3. vn2 的 def 必须是 `CPUI_INDIRECT`（cc:551-552）；
4. 该 INDIRECT 必须标注（mark）的是**正在处理的读 op**——
   `op == get_op_from_const(indop->getIn(1))`（cc:554）；
5. INDIRECT 的 in(0) 对 vn 的 copy shadow /
   partial copy shadow 豁免（cc:555-561，overlaptype 1 与非 1 两形态）。

> 行号勘误（2026-08-30，R-LATTICE-CROSSREVIEW MINOR-1）：上列 cc: 引用原为
> 547/548/549-550/552/553-561（-2 系统漂移），已按锁定 oracle
> `e40ed130` 的 grep -n 实测行号修正为 549/550/551-552/554/555-561；
> src/merge.rs 行内 `cc:` 注释同步修正。守卫顺序与语义不受影响。

此前该分支处于死路径（heritage guard 修复落地前没有 varnode 携带
addrforce 进入该分支），NONCONVERGE 修复后 Ram 全局版本首次激活它，
截断形态把大量非交叉误判为交叉。全量移植后 next_url 的
"Forced merge caused intersection" panic 4→3。残余 3 例
（my_get_token/glob_range/main）的触发=Rugra 保留了第一代 guard 格
（oracle 在 deadcode pass=2 摧毁后由 pass≥3 heritage 重建第二代，
成员里没有 Rugra 多出的 phi——如 my_get_token 0x17510 组的
MULTIEQUAL@0x37b4），归 heritage place_multiequals/rename 代际差异，
另行登记。

## 诊断 TAG 登记（RUGRA_MERGE_DIAG / RUGRA_HERITAGE_TRACE）

> 2026-08-30 转正（R-LATTICE-CROSSREVIEW MINOR-3）：原先标注
> "TEMPORARY … 合入 root 前必须移除" 的 env 门控 stderr 诊断已在集成
> commit 中保留并按 AGENTS.md 调试输出规范（eprintln + 登记 TAG）转正。
> 全部 env 门控、只写 stderr，不污染 stdout 的 C 输出；默认关闭。

| TAG | 门控 | 位置 | 内容 |
|---|---|---|---|
| `[MERGE-FAIL]` | `RUGRA_MERGE_DIAG` | `merge_range_must` 失败前 | 整组 `(space,offset,size)` 成员转储（def/flags/high 实例数，`*FAIL*` 标注） |
| `[MERGE-PAIR]` | `RUGRA_MERGE_DIAG` | `[MERGE-FAIL]` 之后 | 每对相交实例的 def/cover 与读者 op/order |
| `[UNIFY]` | `RUGRA_MERGE_DIAG` | `unify_address` 逐 Ram vn | `descend/marked/ops_delta/flags`（marked = snip_reads 实际剪断的读 op 数，可与 oracle `[ORE-MARK]` 逐行对拍） |
| `[H-GRET]` | `RUGRA_HERITAGE_TRACE` | heritage.rs `rebuild` 通 return 后缀 | pass/range/RETURN 地址（登记于本表以便检索；canonical 归属 heritage 模块文档） |

oracle 侧等价探针（插桩 decomp_opt 的 `[ORE-UNIFY]`/`[ORE-MARK]`/
`[AF-CLEAR]`/`[DEADCODE-ENTER|KILL]`/`[GLOBALTRACE]`）见
/tmp/w-nonconverge2-ore/cpp-dbg（非版本化，重建方式见对拍手册）。

### 2026-08-30：aggregate_high_cover_from 接入惰性 cover 重建（RULE-PROPCOPY-ADDRTIED-0001）
`aggregate_high_cover_from`（Ghidra variable.cc:324 HighVariable::updateInternalCover 的聚合腿）
此前直接读 `inst.cover` 字段 —— 但 Rugra 的 Varnode cover 是惰性的：`calc_cover()` 只置空
Cover+COVERDIRTY，真正的重建在 `Varnode::update_cover_locked`（varnode.cc:233
Varnode::updateCover → cover->rebuild）。跳过它导致聚合 cover 恒为空，所有 cover 门禁
（`merge_test_with_list`/mergeOp 的 trimOpInput lane 裁剪、speculative merge 等）静默放行。
修复：聚合前对每个实例调用 `Varnode::update_cover_locked`（= Ghidra `inst[i]->getCover()`
语义），并忠实 variable.cc:329 的 `inst[0]->hasCover()` 门。效果：ActionMergeRequired 的
`Merge::mergeOp → trimOpInput`（merge.cc:692）恢复对 phi(X,f(X)) 的 lane 裁剪 —— 在 phi
每个入边块尾插 COPY（CMOVcc 惯用法的分支内实例化，curl main/my_get_line/file2string 共
6 处空 if 全部恢复 if 体）。双侧 oracle fixture：tests/oracle/merge_trim_lane_1204.*。

### 2026-09-22：MERGE-COPYNOISE-DIFFHIGH-0001 — compute_varnode_covers 换轨为 oracle 惰性机之积极物化
`compute_varnode_covers` 的 events 式近似实现（def 块 + 读块直算、`max_bi > bi`
索引序 live-out 启发式、无中间块回填、无 MULTIEQUAL 槽位精度）整体删除，
改为物化 oracle 惰性机的产物：`has_cover()` 门 + 缺失时 `calc_cover()`
（varnode.cc:254-263，funcdata_varnode.cc:38-41/52-53 调用位）→ 置
COVERDIRTY → `Varnode::update_cover_locked`（varnode.cc:233 →
cover.cc:477 `Cover::rebuild` 前驱回填）。死代码
`propagate_cover_through_cfg`（自创 successor [0,MAX] 填充，先前已禁用）
与 `op_block_order`（仅近似实现使用）一并移除；`merge.hh:83
Merge::computeVarnodeCovers` 错注更正为 `varnode.cc:233
Varnode::updateCover`。形状回归测试
`test_compute_varnode_covers_backfills_intermediate_blocks` 钉住
def 块 [def,end] / 中间块全块 / 读块 [begin,read] 的 oracle 形状
（旧近似下中间块永无 cover，该测试必败）。

**实证边界（B2 状态如实）**：`merge_all`/`compute_varnode_covers` 在生产
管线零调用（coreaction.rs 走逐 Action 细粒度路径，与 oracle 同构）——
本改动 E2E byte-identical（curl+httpd，defects=0/numbering=0），生产行为
零变化；函数级 NO_ORACLE（无真实 oracle 对拍，仅单测形状断言 +
E2E 不变性证据）。COPY 噪声真根因不在 cover 范围层：探针（/dev/shm/
rugra-tests/sb-copynoise/）测得 CopyMarker 时 1957 个 diff-high 幸存 COPY
中 1531 个的一侧为 implied（mergeTestBasic 正确拒绝），仅 ~312 ok/ok 对
未被合并 —— 主杠杆移至 MarkImplied×打印折叠（printc lane）与 ok/ok 对
的 req/inter/重分裂排查，已在 TODO_BOARD 重新登记。

### 2026-09-22：MERGE-COPYNOISE-IMPLIEDFOLD — merge_test_with_list 接入精确 HighIntersectTest（真根因修复）

**CA 判决修正**：copynoise lane 的"折叠责任在打印侧"推断被双侧实证推翻。
锁定 oracle 直连探针（/dev/shm/rugra-tests/sb-impliedfold/oracle_copyprobe，
git archive e40ed130 + BfdArchitecture）对 main 逐阶段 census：
oracle 进入 merge 组时仅 **190 个存活 COPY**（管线入口 726 ≈ 原始 mov 数
668），MarkImplied 只 imply 22 个 COPY 相关 varnode，mergerequired 全程
仅 +45 op；而 Rugra 在 pre-assignhigh 时与 oracle 几乎一致（8907 vs
8904 ops），**ActionMergeRequired 处爆增 +8809 op**（main +8804）。打印侧
一刀切折叠 in-implied COPY 是错的——oracle 自己打印 20 个合法 in-implied
COPY（RHS 内联 CAST 表达式）。

**根因**：`merge_test_with_list`（Merge::mergeTest port,merge.cc:1657）
绕过了 testCache,用 `aggregate_high_cover`+`intersect_char>0` 粗近似
（任何同块字符重叠 ⇒ 相交）。oracle 的 `testCache.intersection(a,high)`
（variable.cc:1166）= `intersectList(…,2)` 候选块 + `blockIntersection`
（gatherBlockVarnodes + testBlockIntersection,variable.cc:998）做
**实例 def/read 时间戳级**判定——字符重叠但时间戳不交错的 high 对
判"不相交"。粗近似使 mergeOp Phase 2（merge.cc:743-761）对大量时间戳
不相交的 MULTIEQUAL/INDIRECT 误判失败 → trim 循环把每个输入都
trimOpInput → 每 phi 产 2-3 个 COPY trim,main +8804。这些 trim COPY
随后被 MarkImplied 标 implied（单实例 high 的 inflateTest 平凡通过）,
mergeTestBasic 拒绝合并,最终以 `uVarX = uVarX` 自赋值与 spill/restore
乒乓形态泄漏到打印。

**修复**：merge_test_with_list 改走 `self.type_test_cache.intersection`
（Rugra 已有的 HighIntersectTest 忠实 port,mergeType/mergeAddrTied 已在
用）,与 oracle merge.cc:1664 `testCache.intersection(a,high)` 字面一致。

**门禁**：merge_marker trim 全语料 +13870 → **+368**（main +8804→远低
于 oracle +45 量级）；main 存活 COPY 9050→**327**（oracle 234）；curl
全文件自赋值 **907→2**（golden 0；余 2 个在 match_url,绑定既有
PRINTC-CONDBLOCK-JUNKOPS-0001 族）；curl E2E skeleton **3654→3018**,
defects=0/numbering=0；httpd skeleton 2459→2406,defects=0/numbering=0；
--func main 1199→819；glob_set 97→105（重排非缺陷,defects=0,如实报告）；
merge:: 8/8 + coreaction:: 57/57 测试绿；全量 --lib 18 失败为主仓同基
预存在（/home/ls/Rugra d3fbe924 复跑同集合）。改动函数 B2=NO_ORACLE
（无逐函数双侧 oracle fixture;证据=oracle 逐阶段 census 探针 + 双语料
E2E 差分门禁）。

### 2026-09-24（GE / MERGE-LIVEREAD-ORD351-0001）：merge_op Phase 1 输入改活读
`merge_op`（merge.cc:719）Phase 1 的两处输入读取由**循环前快照**改为
**逐迭代活读** `op.0.read().unwrap().inrefs`，逐字镜像 cc:731
`op->getIn(i)->getHigh()` 与 cc:737 `op->getIn(j)->getHigh()`（C++ 每次经
op 解引用取当前 slot 的 Varnode/HighVariable）。原实现把 inrefs 克隆成
`inputs` vec 后在 i/j 两层循环里复用，导致**早先 slot 的 trim 不可见**：
`trim_op_input(op, 0)` 已把 slot 0 换成 trim COPY 输出（allocateCopyTrim
经 wire_unique_high 给全新 HighVariable，无 input/addrtied 旗标），而 j 层
仍拿旧快照里 slot 0 的原 Varnode（如 RSI 函数参数，`is_input=true` 且非
addr-tied）去测后续 slot——`merge_test_required`（cc:125-127
`high_out->isInput() && high_in->isAddrTied() && !high_out->isAddrTied()`）
误判冲突，把本应与 phi 输出同 high 直接合并的 addr-tied 栈读也 trim 成
unique 临时。

**可观测修复**（gp 投影 ord351，getparameter.constprop.0，
universal:mergerequired 阶段）：phi@3f80:189a
`out=n:stack:…fa48 in=[RSI(i), n:stack:…fa48(4030:1892)]`——oracle 仅
trim slot 0（u:10000645=RSI），slot 1（回边栈读）从 SNAP 351 到终态
SNAP 371 保持原栈读直接合并；Rugra 旧代码额外产出
`u:1000064d = s:stack:…fa48(4030:1892)`（trim COPY@4043:1c91）。修复后
gp 投影与锁定 oracle **全 371 阶段逐 snapshot 零差异**（ops 913395→
913373==oracle，MATCH），ord351 首分歧消除；next_url/match_url/
parseconfig 三投影 MATCH 保持，myprogress ord399（setcasts，FV2 域）
不动。curl/httpd E2E 输出与亲父 b25bce7a **cmp 逐字节相同**（1995/0/0、
2072/0/0，corpus-neutral：该 trim COPY 在下游本会被清掉，差异仅在
B2 投影可观测维度）；单测 1687/18 == 亲父同 flaky 集。快照 `inputs` vec
随之删除（唯一消费方即 Phase 1）。


### 2026-09-26 — TOOLS-REFS-DEFSTART-0001 citation re-anchor

- 本模块 3 处 `// Ghidra:` 头注解的 file:line 已重锚到锁定 oracle (e40ed130)
  的函数定义起始行；本文件中同名单点引用同步更新（正文内点引用/区间端点不在
  机制 D checker 范围，遗留见 RULEACTION-ANNO-PROSE-RANGE-0001）。注释-only，零行为变化。

### 2026-09-27 — CANON-REGJUNK 双票 Phase 3 退役的 harness 适配

- `test_merge_marker_unifies_multiequal_io` 在 `run_heritage_direct` 前显式
  `set_input_varnode` 提升注入的 free 寄存器读——inject_raw_ops 的 Phase 3
  线性序输入预提升已整体退役（CANON-REGJUNK-XMM-EXTRAOUT-0001 +
  CANON-REGJUNK-INRAX-LIVEVAR-0001，见 docs/api/funcdata.md 同日注记）；本
  fixture 注入的是合成单块 MULTIEQUAL（SLEIGH 永不产生的形态），heritage 的
  后继边绑定通道（heritage.cc:2531-2552）在该形态下无块边界可走，直接建模
  空栈读的 heritage 后态。断言面（merge_marker 统一 phi 入/出高变量）不变。
