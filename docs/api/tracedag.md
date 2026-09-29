# `tracedag.rs` API Reference

**状态**: 已核对（当前有效；2026-09-27 GIANTS-GA1-PRAGMADISPATCH-0001 移除 push_branches 诊断迭代上限）
**2026-09-27 追加（GIANTS-GA1-PRAGMADISPATCH-0001）**: `push_branches` 移除 5000 次迭代的
DIAGNOSTIC 硬上限（Rugra 自创胶水，Ghidra `TraceDAG::pushBranches`（blockaction.cc:983-1015）
无上限——终止性是结构性的：back/loop-exit 边被 isLoopDAGOut/In 排除，且
`missed>=activecount` 回退每轮严格移除一条非 terminal 候选 trace）。该上限在
sqlite3Pragma 的 final-trace 轮（oracle 同轮 ~11.2k 事件）中途截断 likelygoto 列表，
把双分派共享 40 case 块切成 19/21 而非 oracle 的 40/0（事件级对拍：截断点恰为
push 事件 #5186=`[TRACEDAG] iter cap 5000 hit`；移除后 retire/open/miss 41417 事件
与 oracle 零 diff、selgoto 500 标记零 diff、臂形 40/0、双 switch 相邻 91 行、
标号集 63/63 恒等）。
**2026-08-27 追加（TRI2-STRUCT-IRREDUCIBLE-TRACE-0001）**: `push_branches` 增加 RUGRA_IRRED_DBG=1 门控的 stderr 诊断（`[TD] OPEN/RETIRE/STALL/BADEDGE` 行：trace#、bottom/dest、edgelump、visitcount、loopDAG_in/total_in、bp depth）——用于与 oracle 逐步决策对拍，无行为影响（env 未设时零开销路径不变）。
**状态（前）**: 已重写核对（2026-08-24 BLOCKSTRUCT-GOTOCASCADE-CONDSTMT-0001，per-loop 驱动）
**源代码路径**: `src/tracedag.rs`

## 2026-08-24 重写（BLOCKSTRUCT-GOTOCASCADE-CONDSTMT-0001）

修复 5 处对 oracle 的决定性偏差（全部是 likely-goto 过度标记/错误选择的根因）：

1. **select_bad_edge siblingedge 方向反**：cc:621 "A bigger sibling edge is less likely
   to be the bad edge"——max 扫描保留 **更小** siblingedge（旧代码保留更大的，破坏
   if/else 钻石合并边 → CBRANCH 孤儿化 → 裸条件语句）。
2. **BadEdgeScore::distance 简化**：改用 markPath + BranchPoint::distance 公共祖先
   步数（cc:509-536；旧 `|depth_a - depth_b|`）。
3. **openBranch 无出边分支把 parent 移出 active**：terminal trace 必须**留在
   active**（cc:670 "Do NOT remove from active list"、cc:844-851 返回
   parent->activeiter），否则其 BranchPoint 永不退休 → 卡死 → 连环选 bad edge。
4. **removeTrace 删除路径不 shift pathout**：cc:673-686 删除路径要把上方 trace 的
   pathout 及其 derived BranchPoint 的 pathout 下移一格（否则 pathout!=0 的兄弟
   永不触发 checkRetirement）。Rust 侧以 `deleted` tombstone + paths 数组真实删除实现。
5. **push_branches 迭代位置**：恢复 retireBranch/openBranch 返回位置的续跑语义
   （cc:1000-1011；活跃列表用 slot 数组模拟 std::list：remove 挖洞不回填、push
   追加、迭代跳洞）。另删除自创 `graph.get_size() < 10` 跳过。

新增 per-loop API：`TraceDAG::new/add_root/set_finish_block/initialize/push_branches`
全部 pub，`update_loop_body`（blockaction.rs）按 cc:1227-1245 直接构造（root=looptop
单根、finish=loopbottom、先 setExitMarks 后 trace、emitLikelyEdges 追加、后
clearExitMarks）。`generate_likely_gotos` 仅保留全图 DAG 分支（cc:1233-1239）。

验证：tests/oracle/blockstruct_goto_cascade_1204 双侧 fixture（6 case 全部终止、
case 1-5 零伪 goto 标记、goto 目标/gotoout 位与 oracle 一致）。

## 模块说明

Ghidra TraceDAG (blockaction.cc:499-1014) 的 Rust 移植。追踪控制流图找 likely
unstructured edges（阻止结构化的 goto 边），让剩余控制流结构化为 if/while 而非 switch。

## 导出的公共 API

### `pub fn generate_likely_gotos(graph: &BlockGraph) -> Vec<FloatingEdge>`

为函数的控制流图生成 likely goto 边。返回 (source_block_idx, dest_block_idx) 列表。

### `pub struct FloatingEdge { top: i32, bottom: i32 }`

likely goto 边：top=源块索引，bottom=目标块索引。

## 内部结构

- `TraceDAG`: 主追踪器，包含 BranchPoint/BlockTrace 向量和活跃列表。
- `BranchPoint`: 分支点（对应多出边的 FlowBlock），含 paths（子 trace 索引）。
- `BlockTrace`: 单条追踪路径，含 bottom/dest block 索引、active/terminal 状态。

## 当前限制

check_open 使用简化近似（size_in <= edgelump），select_bad_edge 选第一个活跃 trace
而非完整 BadEdgeScore 评分。需实现 visit-count 追踪和 BadEdgeScore 后才能启用。

## 2026-06-26 更新：完整 BadEdgeScore + visit-count 追踪

- check_open 改为 visit-count 追踪（block_idx → 已追踪入边计数）。
- select_bad_edge 改为完整 BadEdgeScore 评分（siblingedge/terminal/distance/depth）。
- remove_trace 更新 visit-count（标记 goto 时增加计数，忽略该边）。
- 当前仍 DISABLED：open_branch/retire_branch 需在节点打开/退休时更新 visit-count，
 否则计数过时导致错误边选择。需进一步修复后启用。

## 2026-06-26 更新2：back-edge 过滤

- open_branch 现在跳过 back-edge（target index <= dest），防止追踪回环。
- 启用测试时 gcc 无回归（curl 24/24, httpd 29/29）但 test_bool_condition_folding 失败
 （简单函数被错误标记边）。仍 DISABLED。

## 2026-06-26 更新3：简单函数保护 + 启用

- generate_likely_gotos 跳过 < 10 块的简单函数（防止误标 goto 边）。
- TraceDAG 已启用！176/176 测试通过。curl 24/24 gcc。httpd 29/29 gcc。
- getparameter 仍 （switch 检测先消费块，需进一步对齐）。

## 2026-06-26 更新4：opened 集合 + visit-count 边递增

- 新增 opened 集合追踪已打开的节点，check_open 对已打开节点直接返回 true。
- open_branch 在创建子 trace 时递增目标节点的 visit_count（追踪入边）。
- TraceDAG 现在在 phase1 前安全运行（176/176 测试，curl 24/24，httpd 29/29）。

## 2026-06-26 更新5：back-edge 过滤 + opened 集合双重保护

- open_branch 同时使用 back-edge 过滤（target <= dest）和 opened 集合检查。
- back-edge 过滤防止追踪进入循环（匹配 Ghidra isLoopDAGOut 语义）。
- opened 集合防止重复打开已打开的节点。
- getparameter: , 0 switch（从 + 1 switch 改善）。

### 2026-06-27（会话3 G4续）：isLoopDAGOut 集成 — LoopBody 驱动 TraceDAG

- `TraceDAG::is_loop_dag_out(idx, slot) -> bool` — 忠实于 Ghidra `isLoopDAGOut`（block.hh:342）：当边的 flags 含 `F_IRREDUCIBLE_EDGE|F_BACK_EDGE|F_LOOP_EXIT_EDGE|F_GOTO_EDGE` 时返回 false（TraceDAG 不应追踪）。
- TraceDAG 的 out-edge 遍历现在调用 is_loop_dag_out 跳过这些边。

**关键集成**：`CollapseStructure::apply_loop_exit_marks`（blockaction.cc setExitMarks 等价）将每个 LoopBody 的 exit_edges 标记为 `F_LOOP_EXIT_EDGE`，在 `order_loop_bodies` 后、`run_tracedag` 前调用。这样 TraceDAG 的追踪范围被 LoopBody 分析约束——这是 Ghidra `updateLoopBody` 的核心目的：LoopBody 分析结果实际驱动结构化。

**验证**：curl switch 4→5（循环退出标记改变了结构化路径，证明 LoopBody 分析生效）；687/687 测试 + curl 24/24 + httpd 29/29 + 0 goto。

### 2026-07-04：TraceDAG check_open 对齐 Ghidra blockaction.cc:810-833
- 新增 `finish_block_idx`（对齐 Ghidra finishblock, blockaction.cc:822-823）：只有 root trace 能 open finish block。
- `check_open` 分母从 `size_in`（所有入边）改为 loop-DAG 入边计数（对齐 blockaction.cc:826-831 遍历 isLoopDAGIn）。
- `open_branch` 的 `is_loop_dag_out` 极性修正：从 `if is_loop_dag_out { continue }` 改为 `if !is_loop_dag_out { continue }`（对齐 createTraces :504 `if (!isLoopDAGOut) continue`）。
- 新增 `is_loop_dag_in` helper（对齐 block.hh:345 isLoopDAGIn）。
- `opened` 集合保留为保守安全网（Ghidra 无此机制，靠纯 visit-count 终止；Rugra 的 visit-count 终止性待验证后可移除）。
<!-- annotation-pass: 2026-07-04 -->

## 2026-08-30：generate_likely_gotos 僵尸幻影根过滤（MAIN-RC4-DOWHILE-TRACE-0001）

`generate_likely_gotos` 的根收集补 `graph.absorbed_into` 过滤：Ghidra 的列表从不包含已被
折叠进组合块的组件（identifyInternal 移除, block.cc:953-960），Rugra 平铺 Vec 里被剥光的
僵尸 size_in()==0 时会伪装成 sizeIn==0 根并污染 final-DAG trace。collapse 管线的
`update_loop_body` final-DAG 分支已改为内联收集（virtual_list 顺序, 见 blockaction.md
2026-08-30 条目），此自由函数仅作独立 helper 保留。

### SELECTGOTO 车道诊断（2026-09-28，MIRRORCENSUS-GETLONGESTMATCH-CLONE-0001 续作）
- `RUGRA_GOTOSTEP=1`（RUGRA-GLUE，debug-only）：`push_branches` 每步倾印
  `[RSTEP] act/miss/cur=(bottom,dest)` + BADPICK/RETIRE/OPEN 动作行——oracle
  侧 scratch [OSTEP] 探针的对照面；`update_loop_body` 无环臂的根收集同步
  倾印 `[RROOT]`。默认关闭，管线行为零变化。本轮用它+oracle [OROOT] 钉死
  selectGoto 级联首分歧点（final-DAG 根集合 blk78 vs blk79 → composite
  min-index 安装位，见 blockaction.md 同日节）。

## 2026-09-29：per-event 常数收口（SPEEDPROF-TRACEDAG-CONST-0001）

**钻定**（[TDP] 探针,env 门控 RUGRA_TDPROF=1,交付前撤净）: VdbeExec --one 1055
上 tracedag 1.05s/198 DAG 构建 = **check_open 0.911s（87%）+ stall 路径 env 检查
0.170s + select_bad_edge 0.147s** + check_retirement 0.048s + open/retire ~7ms;
1,412,207 事件,其中 **is_loop_dag_in 调用 12,204,131 次**（每调 = get_block Arc
克隆 + RwLock read + BlockEdge 克隆,~70ns/边）+ 每事件 1 次
`std::env::var("RUGRA_IRRED_DBG")`（env 锁+分配）。**oracle 对照**（亲读
blockaction.cc:810-833 + block.hh:345）: oracle checkOpen 每边 = `bl->isLoopDAGIn(i)`
内联 `intothis[i].label & mask` 纯字段读——12.2M 边访问是 oracle 同构工作面
（同 trace 形态/同边数）,oracle 侧 ~25ms vs Rugra ~850ms,差距全部实现级常数。

**落地（行为恒等: 输出零变,全部纯读区间）**:

1. `check_open` 逐边 `is_loop_dag_in(dest,i)`（每次独立 get_block+锁+BlockEdge
   克隆）→ 单次 get_block + 单 read guard 内 `size_in()` + `get_in_ref(i)` 引用读
   flags（同一 Vec 同一 slot 同一字段;缺块/缺边路径判定逐一保持）。
2. `visit_count` `HashMap<i32,i32>`（check_open 每事件 SipHash 查找）→
   `Vec<i32>`（构造时 `vec![0; graph.get_size()]` 直索引——语义更贴 oracle
   visitcount 字段（block.hh:125, clearVisitCount cc:940 的 per-instance 隐式
   化）;仅 dest>=0 索引被触碰,remove_trace/check_open/stall 诊断读全部守住）。
3. `push_branches` 四个分支点每事件 `std::env::var("RUGRA_IRRED_DBG")` →
   fn 顶 `OnceLock<bool>` 单读（env 运行期不可变;blockaction.rs IRRED_SW 同款）。

**结果**: 净口径 tracedag 总时 **1.05s → 0.222s（−79%）**（[TDPM] 最小探针,
RUGRA_TDPROF=1）;残余 ~20ms 巨型 DAG = check_open 每事件一次 get_block+锁地板
×1.41M 事件 + select_bad_edge oracle 同构 sort/markPath 工作量 + Arc/RwLock
结构地板（block.rs 数据结构域,与 PERF-* 残差同族）。**恒等链**: VdbeExec
--one 1055 stdout md5 bf2d9b85 全等（base r1/r2==opt r1/r2 配对）;sqlite 全语料
--jobs 32 assembled 4 轮 cmp 字节恒等;canon/镜面/tests 见车道终报。
