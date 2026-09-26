# `sailr/mod.rs` API Reference

**状态**: 已核对（当前有效）
**源代码路径**: `src/sailr/mod.rs`

## 模块说明 (Module Doc)

**ENHANCEMENT 域 — 无 Ghidra 对照物。** SAILR 增强层：编译器感知结构化算法族
（USENIX 2024 SAILR 论文, mahaloz）的独立移植。RegionIdentifier 结构化区域切分 +
模式化循环恢复（while/do-while/inf-loop 按编译器旋转模式）+ 短路恢复（`&&`/`||`
菱形 CFG）+ switch 模式识别。语义源为 angr
（`angr/analyses/decompiler/structuring/{phoenix,sailr}.py` +
`region_identifier.py`），Rust 建模参考 kuna（`p7_regions` / `p8_structure`）。

该模块**未接入默认反编译管线**（Phase 1: 纯算法 + 单测; lib.rs 仅一行 `mod`
声明）。默认脸仍是忠实 `blockaction` 移植，其对齐纪律不受影响。Phase 2 双脸缝
设计见 `docs/alignment_docs/SAILR_INTEGRATION_DESIGN_2026-09-26.md`。

所有函数均为 `// RUGRA-GLUE: SAILR enhancement layer (enhanced-track, no
Ghidra counterpart; ref: angr <file> / kuna <file>)` 形态注解（ENHANCEMENT
域，逐函数 oracle 对齐纪律不适用；门禁 = 默认脸中性 + 算法正确性单测）。

## 子模块结构

| 文件 | 内容 | 参考 |
|---|---|---|
| `graph.rs` | 可变确定性有向图基底：arena 节点 + `(addr, ident)` 全序、DFS 工具（back edges / 确定性 postorder）、quasi-topological sort（Tarjan SCC + loop-head 展开）、`subgraph_between_nodes`、CHK 支配者 + 增量支配者（dominance frontiers） | angr `GraphUtils` / `utils/doms.py` / networkx；kuna `kuna_regiongraph.rs` |
| `region_id.rs` | RegionIdentifier：把 CFG 的私有副本坍缩为嵌套 `GraphRegion` 树。connected component → supergraph（single-out→single-in 链合并，branchy 边界保留）→ 循环相（back-edge 头、`_natural_loop_subgraph`（可约）/ slice（不可约）分发、`_refine_loop` 三阶段、cyclic region 抽象）→ 无环相（postdom 攀爬 + 增量支配者修补）→ 顶层 region。`cyclic_loops()` 投影给 structurer | angr `region_identifier.py` / `graph_region.py`；kuna `kuna_regionid.rs` |
| `structurer.rs` | 模式结构器：自有工作图（Ghidra `BlockGraph` 形状：in/out 边向量带 goto/back/default 旗标，二元块 out[0]=false/out[1]=true，活跃组件表）上的 schema 级联 | angr `phoenix.py`/`sailr.py`；Ghidra `ruleBlockOr`/`ruleBlockSwitch`/`ruleBlockCat`/`ruleBlockIf(Else)`/`ruleBlockWhileDo`/`ruleBlockDoWhile`/`ruleBlockGoto` 的结构形态；kuna `region_structurer.rs` |

## 结构器 schema 级联（每轮，直至单一入口根 + goto 岛）

1. 短路条件（pre-pass 不动点）— `&&`/`||` 菱形 → 复合条件节点
2. switch-case 恢复（含 terminal continue-case 与 skip-to-exit 虚拟化）
3. 序列链（single-in/single-out 连跑，`isDecisionOut` 守卫）
4. if / if-else（ITE）
5. 循环 schema：inf-loop / do-while / while-do 折叠 + 循环精化
   （二级出口→break、二级锁存→continue、中位入口→goto、异常头入口→goto），
   innermost-first，RI 接地
6. 包装已虚拟化的 goto 边（plain / if-goto / switch 内联 case-goto）
7. 最后手段：虚拟化一条边（SAILR H1 兄弟计数 → H2 后支配计数(封顶) →
   H3 return 边 → 基序，支配层化桶 crossing/secondary）

## 导出的公共 API (Public API)

### `graph.rs`

- `pub struct RegionId(pub u32)` — 折叠 region payload 的不透明句柄。
- `pub enum NodeKind { Block, Multi, Region, Dummy }` — 节点类别（angr
  `TNode`）。
- `pub struct RegionNode` — 工作图节点（kind/addr/ident/外部块 payload/链/
  region payload/branchy 谓词）。
- `pub struct RegionNodeId(pub u32)` / `pub struct NodeKey { addr, ident, id }` /
  `pub struct NodePool` / `pub type NodeSet = BTreeSet<NodeKey>` — arena 与
  确定性序基础设施。
- `pub struct RegionGraph` — networkx `DiGraph` 类似物（插入序邻接、边去重、
  自环、`(addr,ident)` 全序迭代）。
- `pub fn dfs_back_edges(...)` / `pub fn dfs_postorder_deterministic(...)` —
  DFS 工具（子节点按 `(addr,ident)` 序访问）。
- `pub fn quasi_topological_sort(...)` — SCC 塌缩 + loop-head 递归展开的
  准拓扑序。
- `pub fn subgraph_between_nodes(...)` — 从 source 到 frontier（可选含
  frontier）的切片，悬挂剪枝。
- `pub fn immediate_dominators(...)` / `pub fn dominates(...)` — CHK 支配者。
- `pub struct IncrementalDominators` — 增量（后）支配者 + dominance
  frontiers（`graph_updated` 修补 + `verify` 自校验）。

### `region_id.rs`

- `pub struct GraphRegion` — 一个已识别 region（head/graph/successors/
  graph_with_successors/full_graph/cyclic 标志）。
- `pub struct CyclicLoop { head_addr, body, exits }` — 循环 region 在基本块
  地址上的投影（structurer 的精化输入）。
- `pub trait RegionVisitor` — region 树遍历回调（enter/exit/visit_block）。
- `pub struct RegionIdentifier` — 分析本体：
  - `new()` / `set_*` 选项（angr 默认值）/ `set_entry_addr`；
  - `add_synthetic_block` / `add_synthetic_edge` — 合成测试输入；
  - `build_from_cfg(&[(u64, usize, bool)], &[(usize, usize)], u64)` —
    **Phase 2 适配缝**：从通用 CFG 投影（addr/外部索引/branchy 谓词 + 边表 +
    入口）构建工作图；
  - `compute() -> Result<RegionId>` — 运行分析，返回顶层 region；
  - `region(id)` / `get_top_region()` / `get_regions_by_block_addrs()` /
    `walk_blocks(visitor)` / `cyclic_loops()` / `render_tree()` / `node_addr`。

### `structurer.rs`

- `pub enum LoopKind { While, DoWhile, Inf }` — 循环分类（`for` 是 Phase 2
  数据流缝 `init`/`iterate` 钩子的升级目标）。
- `pub enum GotoKind { Plain, Break, Continue }` — 恢复的非结构化跳转类别。
- `pub enum CondExpr { Leaf(CondLeaf), And(..), Or(..) }` + `pub struct
  CondLeaf { addr, external, invert }` — 抽象条件（叶 = 分支块终态条件按址引
  用；`invert` = 否定奇偶；`negate()` = De Morgan 分布）。`Or`/`And` 的选择
  忠实 `BlockGraph::newBlockCondition`（`Or` 当且仅当第二块在第一块的 false
  出边上）。
- `pub enum StructuredNode { Block, Seq, Condition, If, IfElse, Switch,
  WhileDo, DoWhile, InfLoop, Goto }` — 结构化输出 IR，与 `block.rs` 块类别
  一一对应（Seq↔List、Condition↔Condition、If/IfElse↔If、Switch↔Switch、
  WhileDo/DoWhile/InfLoop↔同名、Goto↔Goto）。
- `pub struct SwitchCase { target_addr, is_default, body }` — switch case。
- `pub struct CfgBlock { addr, complex, switch, simple_return, external }` /
  `pub struct CfgEdge { src, dst, default_edge }` / `pub struct SailrInput {
  blocks, edges, entry }` — 输入投影（Phase 2 适配缝：从 `bblocks` 预计算，
  同 `ActionBlockStructure` 为 `CollapseStructure` 预计算的面）。
- `pub struct Structurer`：
  - `new(&SailrInput) -> Result<Structurer>` — 播种工作图（边序 = 输入序，
    out[0]=false/out[1]=true；back edges 由入口 DFS 标定）；
  - `with_cyclic_loops(Vec<CyclicLoop>)` — 附接 RI 循环投影（RI 接地精化；
    退化整体函数 frontier 自动回退结构走查）；
  - `structure() -> Result<Option<StructuredNode>>` — 驱动级联至单一入口根
    （残余组件为 goto 目标岛 — Ghidra 多顶层形态）；`None` = 诚实部分失败
    （调用者回退）。完成后 `classify_gotos` 后处理把循环作用域内的 goto 分
    类为 Break/Continue。

## 门禁

- **默认脸中性**：模块为管线死代码（无管线调用点）；canon 输出字节恒等。
- **算法正确性**：40 个单测覆盖图基底（16）、RegionIdentifier（7）、结构器
  （17：序列/if/if-else、`||` 与 `&&`（De Morgan 形态）菱形、complex 守卫、
  while 两种边向、do-while 两种旋转、inf-loop、多出口→break 精化、多锁存→
  continue 精化、switch、switch-循环 continue-case（getopt 形态）、非结构化
  跳转回退、RI 接地精化）。

## Phase 2 接入缝（预留）

1. `RegionIdentifier::build_from_cfg` ← `Funcdata::bblocks`（每基本块一节
   点，`branchy` 由 tail op 预计算）。
2. `Structurer::new(&SailrInput)` ← 同一 CFG + 预计算事实
   （`complex`=`bb_is_complex`、`switch`=`is_switch_out`+已恢复跳转表、
   `simple_return`）。
3. `StructuredNode` → `block.rs` `BlockGraph` 构件的一一映射 + `CondExpr` →
   P-code 条件恢复（condexe 面）→ printc 消费。
